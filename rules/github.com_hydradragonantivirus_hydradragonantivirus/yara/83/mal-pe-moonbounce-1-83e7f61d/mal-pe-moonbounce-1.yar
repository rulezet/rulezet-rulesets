rule MAL_PE_MOONBOUNCE_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule generated using MCRIT for code family MOONBOUNCE."
    reference   = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/01/19115831/MoonBounce_technical-details_eng.pdf"
    DaysofYARA  = "11/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-27"
    version     = "1.0"

  strings:
        
    $blockhash_0xc6a4421b3d81570f = {
      06 fa 2b 2d ?? ?? ?? ?? 01 33 f9 2a 90 a8 dc 30 b5 1a 6a b6 48 7f ??
    }
    
    $blockhash_0xff1d8fb614f45beb = {
      ce a0 ?? ?? ?? ?? 1d 3d 95 63 5a 07 6b 6b f4 cd f1 c9 3c f1 e3 ??
    }
    
    $blockhash_0x56ba13fa97fe20b  = {
      33 f9 92 b5 ca 39 01 47 88 01 c3
    }
    
    $blockhash_0xf00d0d779418ea5  = {
      d4 06 c5 82 b6 1a d0 d0 24 b4 40 b1 69 3c c8 11 f6 34 00 7f ??
    }
    
    $blockhash_0x353edfa272be4ef  = {
      af 64 d5 89 a7 82 27 fb 1f 09 11 a6 c2 12 e6
    }
    
    $blockhash_0x416174c3dc803e2  = {
      12 06 d9 c4 b6 ae 48 a8 35 4b e9 ?? ?? ?? ??
    }
    
    $blockhash_0x9069437ae5684a02 = {
      ec 2b 4d ba 6c 43 4c e5 61 0a 6b fd c3
    }
    
    $blockhash_0xe94618df08470b78 = {
      d8 9a d4 2b cf 11 06 ef 60 63 29 fa a1 ?? ?? ?? ?? b0 6e 81 17 d1 d5 a8 6a f8 74 ??
    }
    
    $blockhash_0x8e8f21c3c3f1220f = {
      f8 60 b5 06 10 e0 fc 47 e8 ?? ?? ?? ?? ca 6b 7e
    }
    
    $blockhash_0xf4998699aabe0946 = {
      65 12 35 40 93 2c 43 d7 4e a7 4e fa 4e
    }

  condition:
    uint16(0) == 0x5A4D
    and (uint32(uint32(0x3C)) == 0x00004550)
    and uint16(uint32(0x3C) + 0x18) == 0x20b
    and 7 of them
}