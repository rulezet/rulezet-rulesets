rule TTP_XOR_QUAD_CurrentVersionRun_e30c {
  strings:
    $key_e30c = { b0 63 [2] 94 6d [2] bf 41 [2] 91 63 [2] 85 78 [2] 8a 62 [2] 94 7f [2] 96 7e [2] 8d 78 [2] 91 7f [2] 8d 50 }

  condition:
    any of them
}