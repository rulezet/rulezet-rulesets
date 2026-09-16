rule TTP_XOR_QUAD_CurrentVersionRun_0971 {
  strings:
    $key_0971 = { 5a 1e [2] 7e 10 [2] 55 3c [2] 7b 1e [2] 6f 05 [2] 60 1f [2] 7e 02 [2] 7c 03 [2] 67 05 [2] 7b 02 [2] 67 2d }

  condition:
    any of them
}