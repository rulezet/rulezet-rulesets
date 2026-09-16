rule Mimikatz_SampleSet_3: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash        = "f62848e3cd2f0316608c2696c6504b4a"
    score       = 50

  strings:
    $s8 = "x64/intra.kirbi" fullword
    $s9 = "x64/intra.kirbi*kb" fullword

  condition:
    all of them
}