rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_21ea22d345e7_4408 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash3       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash4       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash5       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash6       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash7       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"
    hash8       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"
    hash9       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash10      = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "uck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQ" ascii
    $s2 = "n \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3 = "fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"U" ascii
    $s4 = ",(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck()" ascii
    $s5 = "rn \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}