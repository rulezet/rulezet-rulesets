rule TTP_XOR_QUAD_CurrentVersionRun_d63c {
  strings:
    $key_d63c = { 85 53 [2] a1 5d [2] 8a 71 [2] a4 53 [2] b0 48 [2] bf 52 [2] a1 4f [2] a3 4e [2] b8 48 [2] a4 4f [2] b8 60 }

  condition:
    any of them
}