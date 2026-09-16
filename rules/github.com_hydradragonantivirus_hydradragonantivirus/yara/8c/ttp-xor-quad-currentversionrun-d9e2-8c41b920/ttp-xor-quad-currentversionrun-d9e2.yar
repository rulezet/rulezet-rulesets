rule TTP_XOR_QUAD_CurrentVersionRun_d9e2 {
  strings:
    $key_d9e2 = { 8a 8d [2] ae 83 [2] 85 af [2] ab 8d [2] bf 96 [2] b0 8c [2] ae 91 [2] ac 90 [2] b7 96 [2] ab 91 [2] b7 be }

  condition:
    any of them
}