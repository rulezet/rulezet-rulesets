rule TTP_XOR_QUAD_CurrentVersionRun_2910 {
  strings:
    $key_2910 = { 7a 7f [2] 5e 71 [2] 75 5d [2] 5b 7f [2] 4f 64 [2] 40 7e [2] 5e 63 [2] 5c 62 [2] 47 64 [2] 5b 63 [2] 47 4c }

  condition:
    any of them
}