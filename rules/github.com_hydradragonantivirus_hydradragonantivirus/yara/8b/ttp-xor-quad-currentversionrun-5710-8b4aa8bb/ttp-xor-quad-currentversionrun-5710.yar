rule TTP_XOR_QUAD_CurrentVersionRun_5710 {
  strings:
    $key_5710 = { 04 7f [2] 20 71 [2] 0b 5d [2] 25 7f [2] 31 64 [2] 3e 7e [2] 20 63 [2] 22 62 [2] 39 64 [2] 25 63 [2] 39 4c }

  condition:
    any of them
}