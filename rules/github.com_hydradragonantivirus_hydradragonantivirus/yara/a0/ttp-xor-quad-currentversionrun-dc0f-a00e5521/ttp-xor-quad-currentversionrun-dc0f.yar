rule TTP_XOR_QUAD_CurrentVersionRun_dc0f {
  strings:
    $key_dc0f = { 8f 60 [2] ab 6e [2] 80 42 [2] ae 60 [2] ba 7b [2] b5 61 [2] ab 7c [2] a9 7d [2] b2 7b [2] ae 7c [2] b2 53 }

  condition:
    any of them
}