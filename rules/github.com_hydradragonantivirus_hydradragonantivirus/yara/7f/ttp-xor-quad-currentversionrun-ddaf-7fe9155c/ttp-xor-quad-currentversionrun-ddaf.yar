rule TTP_XOR_QUAD_CurrentVersionRun_ddaf {
  strings:
    $key_ddaf = { 8e c0 [2] aa ce [2] 81 e2 [2] af c0 [2] bb db [2] b4 c1 [2] aa dc [2] a8 dd [2] b3 db [2] af dc [2] b3 f3 }

  condition:
    any of them
}