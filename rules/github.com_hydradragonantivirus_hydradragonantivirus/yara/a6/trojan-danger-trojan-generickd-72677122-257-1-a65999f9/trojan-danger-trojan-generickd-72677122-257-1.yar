rule Trojan_Danger_Trojan_GenericKD_72677122_257_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_257_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4587cb5ec943b162fd191571c6d7cdf8e583a90abfc65dff962ae670d1e2abbf"

  strings:
    $s1  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s2  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s3  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s4  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s5  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s6  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s7  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s8  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s9  = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s10 = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s11 = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s12 = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s13 = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s14 = "}, jibe, 'C:\\\\jenkins\\\\workspace\\\\8-2-build-windows-x64-cygwin-sans-NAS\\\\jdk8u411\\\\893\\\\install\\\\make\\\\smartmake" ascii
    $s15 = ".?AU?$LocaleMatcher@UMatcher@?1??isSupported@Locale@@CA_NGAAV3@@Z@@?A0x370d5050@@" fullword ascii
    $s16 = "GroupTracker<class `anonymous namespace'::UpgradeCodeInstalledJavaTracker<0,64>,class A0x19b40b00::UpgradeCodeInstalledJavaTrack" ascii
    $s17 = "eInstalledJavaTracker<1,32> >,class GroupTracker<class `anonymous namespace'::UpgradeCodeInstalledJavaTracker<0,64>,class A0x19b" ascii
    $s18 = "GroupTracker<class GroupTracker<class `anonymous namespace'::UpgradeCodeInstalledJavaTracker<0,32>,class A0x19b40b00::UpgradeCod" ascii
    $s19 = "GroupTracker<class GroupTracker<class `anonymous namespace'::UpgradeCodeInstalledJavaTracker<0,32>,class A0x19b40b00::UpgradeCod" ascii
    $s20 = "GroupTracker<class `anonymous namespace'::UpgradeCodeInstalledJavaTracker<0,64>,class A0x19b40b00::UpgradeCodeInstalledJavaTrack" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}