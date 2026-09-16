rule infected_10_11_18_620ad_js {
  meta:
    description = "shell2 - file 33706bc2224b7c62a40b422eea79fc5b0e293b2b6041337d8c62eda0dfa620ad.bin"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-11"
    hash1       = "33706bc2224b7c62a40b422eea79fc5b0e293b2b6041337d8c62eda0dfa620ad"

  strings:
    $s1  = "OU1pnTnRoMEhTVjlvb1ZOY3l1d1IwMjBsazFFSUJYSmhVWWZQMG9DMGhiWnRza014NjF2bWYxcVAxdll" fullword ascii  
    $s2  = "3ejRRWEpFdWVHdnZ0bHhIWXR6RVp0cWZOYnVETkp3U0lHeVdaY2RyWGNRNHRaVmVwN2FuSW9CeVdZS04" fullword ascii  
    $s3  = "VK0JON0QzVVk0emJTUjFuWXFjU1RlOG5maGlYMW9CZmsyZXZ6STFhd21CWG1paEVFemJ4d0QrVU9Kb1B" fullword ascii  
    $s4  = "4NjNcMTQxIik/JHkzZTMwNzZlKCRrYjMzNjBmZSgkZzQxMTRkM2QoIkNJVU1lZGdWUmlsS2IvZ2pFbWx" fullword ascii  
    $s5  = "jOC49IlwxNjAiOyRnNDExNGQzZC49Ilx4MzMiOyRrYjMzNjBmZS49Ilx4NjUiOyR0MWZiOWY2ZC49Ilx" fullword ascii  
    $s6  = "TcmRqNmpTYWh0eWpKTVUvR0tvMjhjVFhXSnZ4cEhNVG1CN0lvMHkwM3NFZmRrT2t6T2NIdUVPRGhsU0p" fullword ascii  
    $s7  = "yYygkaTRlNjdhYWMoJHBkY2VlMGM4KCJceDJmXDEzNFx4MjhceDVjXHgyMlw1Nlx4MmFceDVjXHgyMlw" fullword ascii  
    $s8  = "6UzVPTTRONUpYajhxczA3UzhBUzB6b1oxRWJDSkFWTXJpSFhLYWxCeGxLU25ablZHOForSFUwbFhpWnB" fullword ascii  
    $s9  = "2TnBCcmg1bkhxSjZGaDFYZzQ5VFM4cnJCM050eUFaRDJ0NmJWTEkwcjFrb09NdGN5UE11U1lOQzdDaVE" fullword ascii  
    $s10 = "yeFd0cmFLTEVJTDlwa1htejdoQ0VYMTZuQ3o2bUV5aE5LVjZsTjA0SWQraUlZMGkvNW9sbWtFeDVQYWN" fullword ascii  
    $s11 = "zIjskdDFmYjlmNmQ9IlwxNDYiOyR5M2UzMDc2ZT0iXDE0NyI7JGk0ZTY3YWFjPSJceDczIjskZ2VlYjg" fullword ascii  
    $s12 = "OUkl2ei9FTlV0bjVTUDV1NU55VU9lZ1RyQUZieUI4eFlvV2tQQ254dzJiK3lDeWw5Yi9wZmVEKzZEVmt" fullword ascii  
    $s13 = "HbG1BSk82SVFBMWtmbXcyTWRmUFpwOGFzZDdySmtabVYyaktXYlRCMFFhWHBhQzg4b3BXN0o5U0U5UU5" fullword ascii  
    $s14 = "iIiwkdDFmYjlmNmQoJGdjNzhjYTZhKCRsYjYzNDJhNSkpKSkpLCJcNjJcNjFceDY0XDYwXHgzM1w2Nlx" fullword ascii  
    $s15 = "uVFBKYVA4dkIwUEUrUWo0YzB2c2k0YU8xL1liNEE4c0hVMEkwMnFtTUlyNFU0ZzFqOEd3R0EzTU03Wkd" fullword ascii  
    $s16 = "zdVlPTTA3eUpnYTY2YUpnazZmb2RFcjdHcWQvSkhrRURSbWtZam9qd2doV09Fc0gremtYdTdVRmROZUk" fullword ascii  
    $s17 = "6UTRaT2xFelBWWlNpb0xkdk9TREppNzRyTzRTOE5ROXROaTBqL3d1RDR4U3RRa3R5VW1RMkxybEcrZXF" fullword ascii  
    $s18 = "xRXV1NTltRjg3UFBKYUJTNFkxQVJ1QUNoSXNySDE5QjhSZGYrNTkzdG1GZUpDczNmRmRZNTArZzJBc0Z" fullword ascii  
    $s19 = "2ZC49Ilx4NzMiOyRsYjYzNDJhNT0kZ2VlYjgzMGMoIlw1MCIsX19GSUxFX18pO0BldmFsKCRoM2JiZDg" fullword ascii  
    $s20 = "yMFR0b0dpaEUzaDFaMFR2REszRkRCM0gwQ3ZsRDBrK3owWEwxRnBiZGdPRWVTblNRbjE0MnBmeWdZN0c" fullword ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}