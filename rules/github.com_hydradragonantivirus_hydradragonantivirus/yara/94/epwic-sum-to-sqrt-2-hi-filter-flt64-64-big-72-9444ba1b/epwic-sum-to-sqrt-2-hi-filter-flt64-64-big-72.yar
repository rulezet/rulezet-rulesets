rule EPWIC_Sum_to_sqrt_2_hi_filter__flt64___64_big_72_ {
  strings:
    $a0 = { 3f 9c be c8 1f 1f 56 9d 3f af 33 7f 06 d1 ff 47 bf b2 c9 12 92 0d 9f a9 bf da 8a 4e 62 36 c4 ff 3f e9 83 b6 6e 33 65 08 bf da 8a 4e 62 36 c4 ff bf b2 c9 12 92 0d 9f a9 3f af 33 7f 06 d1 ff 47 3f 9c be c8 1f 1f 56 9d }

  condition:
    $a0
}