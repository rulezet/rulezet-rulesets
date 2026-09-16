rule TTP_XOR_QUAD_CurrentVersionRun_7520 {
  strings:
    $key_7520 = { 26 4f [2] 02 41 [2] 29 6d [2] 07 4f [2] 13 54 [2] 1c 4e [2] 02 53 [2] 00 52 [2] 1b 54 [2] 07 53 [2] 1b 7c }

  condition:
    any of them
}