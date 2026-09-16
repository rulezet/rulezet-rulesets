rule VirusShareTrojanDownLoader1061384 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader1061384.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a08b39f4003aeee721df549a4d500708972482b8eb592510c9fe8c508a01ee"

  strings:
    $s1 = "DRINK@8@@@Z+CQ@@BCgW@@@KC94oJSgO@@@KDQcoG@@@BhMNEg0oDw@@Bn4J@@@EKBY@@@oLK@8@@@re@@coFw@@Cn4J@@@EKBY@@@oL3i@lK@4@@@oTB@dybwE@cH4J" ascii
    $s2 = "Selected," fullword wide
    $s3 = "Cancel pls ;)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}