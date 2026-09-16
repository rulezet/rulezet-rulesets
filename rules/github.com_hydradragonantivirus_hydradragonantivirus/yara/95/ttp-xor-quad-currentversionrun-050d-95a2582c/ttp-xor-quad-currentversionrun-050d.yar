rule TTP_XOR_QUAD_CurrentVersionRun_050d {
  strings:
    $key_050d = { 56 62 [2] 72 6c [2] 59 40 [2] 77 62 [2] 63 79 [2] 6c 63 [2] 72 7e [2] 70 7f [2] 6b 79 [2] 77 7e [2] 6b 51 }

  condition:
    any of them
}