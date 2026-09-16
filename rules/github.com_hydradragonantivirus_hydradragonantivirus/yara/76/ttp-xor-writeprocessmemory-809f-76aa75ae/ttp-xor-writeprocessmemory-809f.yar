rule TTP_XOR_WriteProcessMemory_809f {
  strings:
    $key_809f = { d7 ed [2] e5 cf [2] e3 fa [2] cd fa [2] f2 e6 }

  condition:
    any of them
}