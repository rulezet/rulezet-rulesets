rule TTP_XOR_QUAD_CurrentVersionRun_f970 {
  strings:
    $key_f970 = { aa 1f [2] 8e 11 [2] a5 3d [2] 8b 1f [2] 9f 04 [2] 90 1e [2] 8e 03 [2] 8c 02 [2] 97 04 [2] 8b 03 [2] 97 2c }

  condition:
    any of them
}