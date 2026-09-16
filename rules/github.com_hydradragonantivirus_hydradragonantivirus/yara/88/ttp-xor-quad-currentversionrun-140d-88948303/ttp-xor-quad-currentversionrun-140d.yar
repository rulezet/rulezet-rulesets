rule TTP_XOR_QUAD_CurrentVersionRun_140d {
  strings:
    $key_140d = { 47 62 [2] 63 6c [2] 48 40 [2] 66 62 [2] 72 79 [2] 7d 63 [2] 63 7e [2] 61 7f [2] 7a 79 [2] 66 7e [2] 7a 51 }

  condition:
    any of them
}