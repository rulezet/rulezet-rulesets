rule TTP_XOR_QUAD_CurrentVersionRun_110d {
  strings:
    $key_110d = { 42 62 [2] 66 6c [2] 4d 40 [2] 63 62 [2] 77 79 [2] 78 63 [2] 66 7e [2] 64 7f [2] 7f 79 [2] 63 7e [2] 7f 51 }

  condition:
    any of them
}