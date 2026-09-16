rule TTP_XOR_QUAD_CurrentVersionRun_d10c {
  strings:
    $key_d10c = { 82 63 [2] a6 6d [2] 8d 41 [2] a3 63 [2] b7 78 [2] b8 62 [2] a6 7f [2] a4 7e [2] bf 78 [2] a3 7f [2] bf 50 }

  condition:
    any of them
}