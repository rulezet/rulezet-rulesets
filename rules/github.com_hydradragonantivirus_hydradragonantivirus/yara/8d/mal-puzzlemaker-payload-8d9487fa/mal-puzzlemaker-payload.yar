rule MAL_PuzzleMaker_Payload {
  meta:
    description = "track the PuzzleMaker payload based on some cryptography API calls and a subroutine in a case (maybe a command?) statement"
    author      = "Greg Lesnewich"
    date        = "2023-01-13"
    version     = "1.0"
    reference   = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
    hash        = "2ae29e697c516dc79c6fbf68f951a5f592f151abd81ed943c2fdd225c5d4d391"
    hash        = "8a17279ba26c8fbe6966ea3300fdefb1adae1b3ed68f76a7fc81413bd8c1a5f6"
    hash        = "f2ce2a00de8673f52d37911f3e0752b8dfab751b2a17e719a565b4083455528e"

  strings:
    $case_statement = { 33 db 4? 8d 4? ?? 80 7? 00 01 8b fb 41 8b d4 4? 8b ce 40 0f 94 ?? 41 80 f9 15 89 7c ?4 20 0f 94 ?? 44 8b cb }
    

    $cryptography = { 41 b9 01 00 00 00 c7 44 ?4 20 00 00 00 f0 45 33 c0 4? 8d 4c ?4 60 33 d2 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8b 4c ?4 60 4? 8d 85 b0 00 00 00 ba 20 00 00 00 ff 15 ?? ?? ?? ?? 4? 8b 4c ?4 60 33 d2 }
  

  condition:
    uint16be(0x0) == 0x4d5a and
    1 of them
}