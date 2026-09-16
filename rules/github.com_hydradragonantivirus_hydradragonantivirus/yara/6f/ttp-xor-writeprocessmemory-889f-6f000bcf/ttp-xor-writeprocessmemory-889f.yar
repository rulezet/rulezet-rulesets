rule TTP_XOR_WriteProcessMemory_889f {
  strings:
    $key_889f = { df ed [2] ed cf [2] eb fa [2] c5 fa [2] fa e6 }

  condition:
    any of them
}