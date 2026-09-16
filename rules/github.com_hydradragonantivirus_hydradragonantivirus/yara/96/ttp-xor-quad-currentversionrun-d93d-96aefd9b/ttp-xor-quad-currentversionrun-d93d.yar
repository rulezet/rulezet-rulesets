rule TTP_XOR_QUAD_CurrentVersionRun_d93d {
  strings:
    $key_d93d = { 8a 52 [2] ae 5c [2] 85 70 [2] ab 52 [2] bf 49 [2] b0 53 [2] ae 4e [2] ac 4f [2] b7 49 [2] ab 4e [2] b7 61 }

  condition:
    any of them
}