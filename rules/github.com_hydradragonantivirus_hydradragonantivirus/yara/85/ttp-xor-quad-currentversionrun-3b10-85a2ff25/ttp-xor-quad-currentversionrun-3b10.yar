rule TTP_XOR_QUAD_CurrentVersionRun_3b10 {
  strings:
    $key_3b10 = { 68 7f [2] 4c 71 [2] 67 5d [2] 49 7f [2] 5d 64 [2] 52 7e [2] 4c 63 [2] 4e 62 [2] 55 64 [2] 49 63 [2] 55 4c }

  condition:
    any of them
}