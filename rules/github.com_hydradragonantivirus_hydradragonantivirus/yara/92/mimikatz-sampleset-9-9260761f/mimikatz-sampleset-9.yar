rule Mimikatz_SampleSet_9: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    super_rule  = 1
    hash0       = "6e2eda476c141c63ff62c92d8b52ff7e"
    hash1       = "f42b75103230cab39e4c58d5b0dca2c4"
    hash2       = "dc6f62e3a0b584cb134633a12fd7d7b8"
    hash3       = "d5918d735a23f746f0e83f724c4f26e5"
    hash4       = "e98b714ccd14e61f776cc55a602d2dd0"
    hash5       = "09a6e5cc589a485d9ab4eda772b46f2a"
    hash6       = "4a51faef37af8b70fc9cf7c64f030b25"
    hash7       = "e52e30811287426d4eef089a65cc2acf"
    hash8       = "cd1606a1800150a33dea71d3f3ee9aed"
    hash9       = "510fe825464dca92aadcd3d8289405aa"
    hash10      = "0be87e16eb598006358cdaa9dfcd5af5"
    hash11      = "1f0ce022ee9fe8d92235809eda73ce38"
    hash12      = "e172a38ade3aa0a2bc1bf9604a54a3b5"
    hash13      = "de20bddb9c3b1b09d980db5bbb5b5789"
    hash14      = "c77db1ddffc7e6edac60bb5ca9a6e863"
    hash15      = "6d8008edd86c5ca1a112018852777b1e"
    hash16      = "525d6ca1446b01f912303f04f0c713ab"
    score       = 70

  strings:
    $s6 = "\\i386\\mimidrv.pdb"

  condition:
    all of them
}