rule TTP_XOR_QUAD_CurrentVersionRun_c20f {
  strings:
    $key_c20f = { 91 60 [2] b5 6e [2] 9e 42 [2] b0 60 [2] a4 7b [2] ab 61 [2] b5 7c [2] b7 7d [2] ac 7b [2] b0 7c [2] ac 53 }

  condition:
    any of them
}