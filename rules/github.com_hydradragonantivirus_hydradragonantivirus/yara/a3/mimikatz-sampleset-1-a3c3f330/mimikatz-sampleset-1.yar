rule Mimikatz_SampleSet_1: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash1       = "9ef9762169e8b44d01613234927f44d6"
    hash2       = "35b34bb9f1ad0fdf48dc090ed4a8190f"
    hash3       = "516fde1fe06f96a019c3ad063c78b760"
    hash4       = "faf248ee5184b65d28786d91c02864a6"
    hash5       = "5847659129c4e711809ab5b6ab1b8bd8"
    score       = 80

  strings:
    $s0 = "mimikatz_trunk/Win32/mimidrv.sys" fullword
    $s1 = "Mimikatz 2.0\\x64\\mimidrv.sys" fullword
    $s2 = "32\\kelloworld.dll"
    $s3 = "64\\kelloworld.dll"
    $s4 = "32/kelloworld.dll"
    $s5 = "64/kelloworld.dll"
    $s6 = "mimidrv.sys" fullword
    $s7 = "sekurlsa.lib" fullword
    $s8 = "mimilib.dll" fullword
    $s9 = "mimikatz.exe" fullword

  condition:
    3 of them
}