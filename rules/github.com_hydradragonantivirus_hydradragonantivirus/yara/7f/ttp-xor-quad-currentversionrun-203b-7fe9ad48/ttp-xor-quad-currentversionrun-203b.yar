rule TTP_XOR_QUAD_CurrentVersionRun_203b {
  strings:
    $key_203b = { 73 54 [2] 57 5a [2] 7c 76 [2] 52 54 [2] 46 4f [2] 49 55 [2] 57 48 [2] 55 49 [2] 4e 4f [2] 52 48 [2] 4e 67 }

  condition:
    any of them
}