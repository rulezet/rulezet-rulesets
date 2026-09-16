rule TTP_XOR_QUAD_CurrentVersionRun_3971 {
  strings:
    $key_3971 = { 6a 1e [2] 4e 10 [2] 65 3c [2] 4b 1e [2] 5f 05 [2] 50 1f [2] 4e 02 [2] 4c 03 [2] 57 05 [2] 4b 02 [2] 57 2d }

  condition:
    any of them
}