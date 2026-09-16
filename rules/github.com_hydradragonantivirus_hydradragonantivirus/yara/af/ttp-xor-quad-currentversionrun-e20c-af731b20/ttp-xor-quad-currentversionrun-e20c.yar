rule TTP_XOR_QUAD_CurrentVersionRun_e20c {
  strings:
    $key_e20c = { b1 63 [2] 95 6d [2] be 41 [2] 90 63 [2] 84 78 [2] 8b 62 [2] 95 7f [2] 97 7e [2] 8c 78 [2] 90 7f [2] 8c 50 }

  condition:
    any of them
}