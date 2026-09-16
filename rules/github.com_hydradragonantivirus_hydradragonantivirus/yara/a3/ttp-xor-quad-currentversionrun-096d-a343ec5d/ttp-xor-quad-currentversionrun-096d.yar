rule TTP_XOR_QUAD_CurrentVersionRun_096d {
  strings:
    $key_096d = { 5a 02 [2] 7e 0c [2] 55 20 [2] 7b 02 [2] 6f 19 [2] 60 03 [2] 7e 1e [2] 7c 1f [2] 67 19 [2] 7b 1e [2] 67 31 }

  condition:
    any of them
}