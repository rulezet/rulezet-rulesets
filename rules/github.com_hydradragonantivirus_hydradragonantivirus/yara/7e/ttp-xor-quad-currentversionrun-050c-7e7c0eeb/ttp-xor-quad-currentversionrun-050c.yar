rule TTP_XOR_QUAD_CurrentVersionRun_050c {
  strings:
    $key_050c = { 56 63 [2] 72 6d [2] 59 41 [2] 77 63 [2] 63 78 [2] 6c 62 [2] 72 7f [2] 70 7e [2] 6b 78 [2] 77 7f [2] 6b 50 }

  condition:
    any of them
}