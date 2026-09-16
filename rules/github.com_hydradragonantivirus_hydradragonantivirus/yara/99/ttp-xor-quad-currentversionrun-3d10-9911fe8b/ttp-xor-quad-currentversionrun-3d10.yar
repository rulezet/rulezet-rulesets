rule TTP_XOR_QUAD_CurrentVersionRun_3d10 {
  strings:
    $key_3d10 = { 6e 7f [2] 4a 71 [2] 61 5d [2] 4f 7f [2] 5b 64 [2] 54 7e [2] 4a 63 [2] 48 62 [2] 53 64 [2] 4f 63 [2] 53 4c }

  condition:
    any of them
}