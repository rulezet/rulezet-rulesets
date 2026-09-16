rule TTP_XOR_QUAD_CurrentVersionRun_3c0d {
  strings:
    $key_3c0d = { 6f 62 [2] 4b 6c [2] 60 40 [2] 4e 62 [2] 5a 79 [2] 55 63 [2] 4b 7e [2] 49 7f [2] 52 79 [2] 4e 7e [2] 52 51 }

  condition:
    any of them
}