rule TTP_XOR_QUAD_CurrentVersionRun_121b {
  strings:
    $key_121b = { 41 74 [2] 65 7a [2] 4e 56 [2] 60 74 [2] 74 6f [2] 7b 75 [2] 65 68 [2] 67 69 [2] 7c 6f [2] 60 68 [2] 7c 47 }

  condition:
    any of them
}