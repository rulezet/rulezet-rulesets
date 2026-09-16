rule TTP_XOR_QUAD_CurrentVersionRun_e611 {
  strings:
    $key_e611 = { b5 7e [2] 91 70 [2] ba 5c [2] 94 7e [2] 80 65 [2] 8f 7f [2] 91 62 [2] 93 63 [2] 88 65 [2] 94 62 [2] 88 4d }

  condition:
    any of them
}