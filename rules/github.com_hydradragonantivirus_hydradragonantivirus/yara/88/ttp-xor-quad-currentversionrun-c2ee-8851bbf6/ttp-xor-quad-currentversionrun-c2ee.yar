rule TTP_XOR_QUAD_CurrentVersionRun_c2ee {
  strings:
    $key_c2ee = { 91 81 [2] b5 8f [2] 9e a3 [2] b0 81 [2] a4 9a [2] ab 80 [2] b5 9d [2] b7 9c [2] ac 9a [2] b0 9d [2] ac b2 }

  condition:
    any of them
}