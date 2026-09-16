rule TTP_XOR_QUAD_CurrentVersionRun_d93c {
  strings:
    $key_d93c = { 8a 53 [2] ae 5d [2] 85 71 [2] ab 53 [2] bf 48 [2] b0 52 [2] ae 4f [2] ac 4e [2] b7 48 [2] ab 4f [2] b7 60 }

  condition:
    any of them
}