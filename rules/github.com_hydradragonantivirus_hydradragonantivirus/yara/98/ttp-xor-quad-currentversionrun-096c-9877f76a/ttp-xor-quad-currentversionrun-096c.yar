rule TTP_XOR_QUAD_CurrentVersionRun_096c {
  strings:
    $key_096c = { 5a 03 [2] 7e 0d [2] 55 21 [2] 7b 03 [2] 6f 18 [2] 60 02 [2] 7e 1f [2] 7c 1e [2] 67 18 [2] 7b 1f [2] 67 30 }

  condition:
    any of them
}