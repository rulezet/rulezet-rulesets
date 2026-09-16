rule TTP_XOR_QUAD_CurrentVersionRun_d9fe {
  strings:
    $key_d9fe = { 8a 91 [2] ae 9f [2] 85 b3 [2] ab 91 [2] bf 8a [2] b0 90 [2] ae 8d [2] ac 8c [2] b7 8a [2] ab 8d [2] b7 a2 }

  condition:
    any of them
}