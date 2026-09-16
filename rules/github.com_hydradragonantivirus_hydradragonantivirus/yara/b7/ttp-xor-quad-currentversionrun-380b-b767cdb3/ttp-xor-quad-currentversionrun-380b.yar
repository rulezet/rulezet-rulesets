rule TTP_XOR_QUAD_CurrentVersionRun_380b {
  strings:
    $key_380b = { 6b 64 [2] 4f 6a [2] 64 46 [2] 4a 64 [2] 5e 7f [2] 51 65 [2] 4f 78 [2] 4d 79 [2] 56 7f [2] 4a 78 [2] 56 57 }

  condition:
    any of them
}