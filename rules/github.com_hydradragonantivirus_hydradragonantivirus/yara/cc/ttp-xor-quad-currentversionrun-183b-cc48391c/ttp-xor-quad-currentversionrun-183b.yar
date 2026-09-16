rule TTP_XOR_QUAD_CurrentVersionRun_183b {
  strings:
    $key_183b = { 4b 54 [2] 6f 5a [2] 44 76 [2] 6a 54 [2] 7e 4f [2] 71 55 [2] 6f 48 [2] 6d 49 [2] 76 4f [2] 6a 48 [2] 76 67 }

  condition:
    any of them
}