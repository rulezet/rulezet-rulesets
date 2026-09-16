rule TTP_XOR_QUAD_CurrentVersionRun_d93b {
  strings:
    $key_d93b = { 8a 54 [2] ae 5a [2] 85 76 [2] ab 54 [2] bf 4f [2] b0 55 [2] ae 48 [2] ac 49 [2] b7 4f [2] ab 48 [2] b7 67 }

  condition:
    any of them
}