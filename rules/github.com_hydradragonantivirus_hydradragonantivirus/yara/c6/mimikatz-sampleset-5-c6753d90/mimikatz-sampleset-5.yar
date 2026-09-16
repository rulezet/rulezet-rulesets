rule Mimikatz_SampleSet_5: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash1       = "9ca015f05cc4cbae8d50bcd067e6d605"
    score       = 50

  strings:
    $s6 = "mimidrv.sys" fullword

  condition:
    all of them
}