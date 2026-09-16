rule TTP_XOR_QUAD_CurrentVersionRun_dcaf {
  strings:
    $key_dcaf = { 8f c0 [2] ab ce [2] 80 e2 [2] ae c0 [2] ba db [2] b5 c1 [2] ab dc [2] a9 dd [2] b2 db [2] ae dc [2] b2 f3 }

  condition:
    any of them
}