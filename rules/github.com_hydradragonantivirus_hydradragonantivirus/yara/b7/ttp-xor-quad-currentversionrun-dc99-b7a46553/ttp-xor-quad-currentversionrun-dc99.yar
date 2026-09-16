rule TTP_XOR_QUAD_CurrentVersionRun_dc99 {
  strings:
    $key_dc99 = { 8f f6 [2] ab f8 [2] 80 d4 [2] ae f6 [2] ba ed [2] b5 f7 [2] ab ea [2] a9 eb [2] b2 ed [2] ae ea [2] b2 c5 }

  condition:
    any of them
}