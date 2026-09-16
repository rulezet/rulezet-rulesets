rule TTP_XOR_QUAD_CurrentVersionRun_9efe {
  strings:
    $key_9efe = { cd 91 [2] e9 9f [2] c2 b3 [2] ec 91 [2] f8 8a [2] f7 90 [2] e9 8d [2] eb 8c [2] f0 8a [2] ec 8d [2] f0 a2 }

  condition:
    any of them
}