rule TTP_XOR_QUAD_CurrentVersionRun_3d62 {
  strings:
    $key_3d62 = { 6e 0d [2] 4a 03 [2] 61 2f [2] 4f 0d [2] 5b 16 [2] 54 0c [2] 4a 11 [2] 48 10 [2] 53 16 [2] 4f 11 [2] 53 3e }

  condition:
    any of them
}