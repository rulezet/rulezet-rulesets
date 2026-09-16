rule TTP_XOR_QUAD_CurrentVersionRun_300d {
  strings:
    $key_300d = { 63 62 [2] 47 6c [2] 6c 40 [2] 42 62 [2] 56 79 [2] 59 63 [2] 47 7e [2] 45 7f [2] 5e 79 [2] 42 7e [2] 5e 51 }

  condition:
    any of them
}