rule TTP_XOR_QUAD_CurrentVersionRun_f871 {
  strings:
    $key_f871 = { ab 1e [2] 8f 10 [2] a4 3c [2] 8a 1e [2] 9e 05 [2] 91 1f [2] 8f 02 [2] 8d 03 [2] 96 05 [2] 8a 02 [2] 96 2d }

  condition:
    any of them
}