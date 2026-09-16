rule MAL_PuzzleMaker_Launcher {
  meta:
    description = "track the PuzzleMaker launcher based on its call to interact with the WMI namespace (CLSID_WbemLocator via CoCreateInstance)"
    author      = "Greg Lesnewich"
    date        = "2023-01-13"
    version     = "1.0"
    reference   = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
    hash        = "982f7c4700c75b81833d5d59ad29147c392b20c760fe36b200b541a0f841c8a9"
    hash        = "44d9f36c088dd420ad96a8518df7e9155145e04db788a99a8f8f99179427a447"
    hash        = "bab8ad15015589e3f70643e6b59a5a37ab2c5a9cf799e0472cb9c1a29186babc"

  strings:
    $call_CoCreateInstance_WbemLocator = { 4? 89 6d bf 4? 8d 45 bf 4? 89 44 ?4 20 4? 8d 0d ?? ?? ?? ?? 33 d2 44 8d 42 01 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d8 85 c0 }
    
    $CreateService                     = { 4? 89 6c ?4 60 4? 8d 05 ?? ?? ?? ?? 4? 89 6c ?4 58 4? 8d 15 ?? ?? ?? ?? 4? 89 6c ?4 50 41 b9 ff 01 0f 00 4? 89 6c ?4 48 4? 8b cf 4? 89 6c ?4 40 4? 89 74 ?4 38 44 89 6c ?4 30 c7 44 ?4 28 02 00 00 00 c7 44 ?4 20 10 00 00 00 ff 15 }
  

  condition:
    uint16be(0x0) == 0x4d5a and
    1 of them
}