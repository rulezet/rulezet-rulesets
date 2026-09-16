rule tree8 {
  strings:
    $s0    = "kSecAttrAuthenticationTypeNTLM" fullword
    $s1    = "objectForKeyedSubscript" fullword
    $s2    = "supportsUIRestoring" fullword
    $s3    = "category23default" fullword
    $s4    = "performActionForShortcutItem" fullword
    $s5    = "UHAWAVAUATSH8IHH" fullword
    $s6    = "scanUnicodeCharacter" fullword
    $s7    = "CreateDeviceAsyncEventSource" fullword
    $s8    = "getblocktemplate" fullword
    $s9    = "KGWindowsController" fullword
    $s10   = "setStandardOutput" fullword
    $s11   = "linenoiseEditMoveRight" fullword
    $s12   = "contentsOfDirectoryAtPath" fullword
    $s13   = "kZBVTInstallerDownloadPathKey" fullword
    $s14   = "GenerateConnectionID" fullword
    $s15   = "IORegistryEntryCreateCFProperty" fullword
    $s16   = "140129192647Z0A1" fullword
    $s17   = "isAppStoreDistribution" fullword
    $s18   = "columnIndexForName" fullword
    $s19   = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s20   = "overrideYahooURL" fullword
    $s21   = "ZBLocalizedString" fullword
    $s22   = "EqualizationPhase1" fullword
    $s23   = "ZN10CryptoNote16ConnectExceptionD1Ev" fullword
    $s24   = "NetworkExtension" fullword
    $s25   = "ponponqqtsrtsruuxwvwvyy" fullword
    $s26   = "setInnvcx4sqaCHC" fullword
    $s27   = "34MutableTransactionSignatureCreator" fullword
    $s29   = "retainAutoreleasedReturnValue" fullword
    $s30   = "ApplicationServices" fullword
    $s31   = "registerForMessageName" fullword
    $s32   = "0123456789abcdef" fullword
    $s33   = "launchJavaApplication" fullword
    $s34   = "AssemblyProductAttribute" fullword
    $s35   = "UserNotifications" fullword
    $s36   = "ZBSafeConnectionRootProxyStateDidChangeNotification" fullword
    $s37   = "sqhIJsyyeFaPcYe7" fullword
    $s38   = "getAuthorization" fullword
    $s40   = "UHAWAVAUATSHHHuE" fullword
    $s41   = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s42   = "HMHMHMHMHMHMHMHML" fullword
    $s43   = "HEHEHEHEHEHEHEHE" fullword
    $s44   = "navigationBarNodeSortingOrder" fullword
    $s45   = "copyElephantBrain" fullword
    $s46   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s47   = "substringToIndex" fullword
    $s48   = "addCleanerRemovedSize" fullword
    $s49   = "certificateauthority" fullword
    $s50   = "HMHMHMHMHMHMHMHMH" fullword
    $s51   = "UHAWAVAUATSHhDMLpHMHUHuE" fullword
    $s52   = "libswiftCoreGraphics" fullword
    $s53   = "140213191008Z0A1" fullword
    $s54   = "dictionaryWithContentsOfFile" fullword
    $s55   = "applicationShouldHandleReopen" fullword
    $s56   = "MacKeeperPrivilegedHelper" fullword
    $s57   = "countByEnumeratingWithState" fullword
    $s58   = "certificateauthority0" fullword
    $s59   = "getInitializedObjCClass" fullword
    $s60   = "e4zPO0A75QibEoIM1dS3ccGV3ag" fullword
    $s61   = "UHAWAVAUATSPDEAI" fullword
    $s62   = "getTupleTypeMetadata2" fullword
    $s63   = "DefaultRuneLocale" fullword
    $s64   = "stringWithFormat" fullword
    $s65   = "kCFAllocatorDefault" fullword
    $s66   = "PrivateFrameworks" fullword
    $s67   = "350209214036Z0b1" fullword
    $s68   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s69   = "systemFontOfSize" fullword
    $s70   = "AuthorizationFree" fullword
    $s71   = "CFConstantStringClassReference" fullword
    $s72   = "ZN16QLoggingCategoryD1Ev" fullword
    $s73   = "CFStringGetCString" fullword
    $s74   = "NSStringFromClass" fullword
    $s75   = "CFBundleIdentifier" fullword
    $s76   = "localizedStringForKey" fullword
    $s77   = "UHAWAVAUATSPIHIH" fullword
    $s78   = "MobileCoreServices" fullword
    $s79   = "9allocatorIcEEEC1ERKS5" fullword
    $s80   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s81   = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s82   = "ZL12cxxConstructP11objc" fullword
    $s83   = "JSObjectSetProperty" fullword
    $s84   = "libswiftDispatch" fullword
    $s85   = "numberWithDouble" fullword
    $s88   = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s89   = "conformsToProtocol" fullword
    $s90   = "ZN9QListData7disposeEPNS" fullword
    $s91   = "loadWeakRetained" fullword
    $s92   = "NSAddressOfSymbol" fullword
    $s93   = "FromStringAndSize" fullword
    $s94   = "iPhoneSimulator10" fullword
    $s95   = "retainAutoreleaseReturnValue" fullword
    $s97   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s98   = "9allocatorIcEEEE" fullword
    $s99   = "lswiftObjectiveC" fullword
    $s100  = "arrayWithObjects" fullword
    $s101  = "ServiceManagement" fullword
    $s102  = "UHAWAVAUATSH8IIH" fullword
    $s107  = "retainAutorelease" fullword
    $s108  = "intrinsicContentSize" fullword
    $s136  = "ecpointformatlist" fullword
    $s137  = "UHAWAVAUATSPIIHt" fullword
    $s138  = "stringWithUTF8String" fullword
    $s139  = "respondsToSelector" fullword
    $s140  = "traitsIcEEE3putEc" fullword
    $s141  = "NSConcreteGlobalBlock" fullword
    $s142  = "IOServiceGetMatchingServices" fullword
    $s145  = "ZN9QListData11shared" fullword
    $s149  = "logKextUserClient" fullword
    $s155  = "ddddddddddddddddddddddddddddddddsd" fullword
    $s156  = "sharedApplication" fullword
    $s157  = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s158  = "debugDescription" fullword
    $s160  = "CFStringCreateWithCString" fullword
    $s161  = "initWithContentsOfURL" fullword
    $s162  = "UHAWAVAUATSH8HIH" fullword
    $s166  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s167  = "autoreleasePoolPop" fullword
    $s169  = "UIViewController" fullword
    $s170  = "UHAWAVAUATSPIIID" fullword
    $s171  = "ImageCaptureCore" fullword
    $s173  = "replaceCharactersInRange" fullword
    $s174  = "SystemConfiguration" fullword
    $s178  = "DisableThreadLibraryCalls" fullword
    $s179  = "NSNotificationCenter" fullword
    $s181  = "DEDEDEDEDEDEDEDE9E" fullword
    $s182  = "fileExistsAtPath" fullword
    $s293  = "200219223002Z0B1" fullword
    $s294  = "libswiftCoreFoundation" fullword
    $s297  = "withIntermediateDirectories" fullword
    $s303  = "UHAWAVAUATSPAAII" fullword
    $s306  = "certificationauthority" fullword
    $s309  = "191128154500Z0A1" fullword
    $s315  = "CFURLGetFileSystemRepresentation" fullword
    $s316  = "180123004003Z0A1" fullword
    $s360  = "270201221215Z0y1" fullword
    $s374  = "NSDistributedNotificationCenter" fullword
    $s378  = "arrayWithCapacity" fullword
    $s390  = "CFBundleInfoDictionaryVersion" fullword
    $s405  = "CFBundleShortVersionString" fullword
    $s407  = "fileHandleForReading" fullword
    $s423  = "replacementString" fullword
    $s427  = "KhfCECHKJKnKtDkW" fullword
    $s460  = "CFStringMakeConstantString" fullword
    $s467  = "OSAtomicDecrement32" fullword
    $s477  = "NSAutoreleasePool" fullword
    $s480  = "createFileAtPath" fullword
    $s491  = "deletedMethodError" fullword
    $s496  = "NSRunningApplication" fullword
    $s501  = "scheduledTimerWithTimeInterval" fullword
    $s502  = "UILocalizedButton" fullword
    $s514  = "scanJSONKeyValueSeparator" fullword
    $s515  = "GCCopyAppDataDir" fullword
    $s516  = "ZNK2cv3Mat5MStepixEi" fullword
    $s517  = "N4laya11JSCFunctionIPFlllbEEE" fullword
    $s518  = "ZN11DbMpoolFile3getEPjP5DbTxnjPv" fullword
    $s519  = "kZBSizeStringKey" fullword
    $s520  = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s523  = "UHAWAVAUATSPIIIu0Ht" fullword
    $s524  = "headerViewController" fullword
    $s525  = "4sxpkxaSWLSlAJiaKPaIibCAcmY" fullword
    $s526  = "NSLayoutConstraint" fullword
    $s527  = "20191105000000Z0" fullword
    $s528  = "140305162647Z0A1" fullword
    $s529  = "CFBundleCopyResourceURL" fullword
    $s530  = "threadSafeMainBundle" fullword
    $s531  = "LSGetCurrentApplicationASN" fullword
    $s532  = "UHAWAVAUATSPAIIHuA" fullword
    $s534  = "cCFAttributedStringMBS" fullword
    $s535  = "lastCrcListValuesCount" fullword
    $s536  = "CFBundleExecutable" fullword
    $s537  = "resignFirstResponder" fullword
    $s538  = "handleHomeButtonSinglePressUp" fullword
    $s539  = "previousblockhash" fullword
    $s540  = "kMDItemWhereFroms" fullword
    $s541  = "SMSTSoSSSSSSSS7U" fullword
    $s542  = "arrayOfDictionariesByMatchingRegex" fullword
    $s549  = "djwIcRRRRRRRRRRRRRRK" fullword
    $s551  = "objectAtIndexedSubscript" fullword
    $s552  = "constructInstance" fullword
    $s553  = "N5boost9exceptionE" fullword
    $s557  = "AECreateAppleEvent" fullword
    $s562  = "selectorPFP11objc" fullword
    $s565  = "autoreleaseReturnValue" fullword
    $s569  = "stringWithString" fullword
    $s570  = "adjustsLetterSpacingToFitWidth" fullword
    $s575  = "traitsIcEEE5tellgEv" fullword
    $s576  = "9allocatorIcEEEEPNS0" fullword
    $s581  = "UHAWAVAUATSH8IHuIH" fullword
    $s587  = "textFieldDidEndEditing" fullword
    $s588  = "NSFetchedPropertyDescription" fullword
    $s597  = "enumerationMutation" fullword
    $s599  = "ellipticcurvelist" fullword
    $s604  = "alSourceQueueBuffers" fullword
    $s665  = "StringCharCodeAt" fullword
    $s671  = "ZL30NSUndoManagerProxy" fullword
    $s683  = "GetEnvironmentVariable" fullword
    $s685  = "completionHandler" fullword
    $s688  = "CFNumberGetValue" fullword
    $s691  = "CFBundleCopyBundleURL" fullword
    $s698  = "ZTVN14RegisterResult16RegistrationDataE" fullword
    $s701  = "CGContextFillPath" fullword
    $s705  = "NSMutableOrderedSet" fullword
    $s718  = "CFArrayGetValueAtIndex" fullword
    $s722  = "gestureRecognizer" fullword
    $s723  = "mediumspringgreen" fullword
    $s724  = "glFramebufferTextureLayer" fullword
    $s743  = "terminationStatus" fullword
    $s744  = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s803  = "UHAWAVAUATSPIHIIH" fullword
    $s805  = "NSMutableURLRequest" fullword
    $s831  = "getCursorPosition" fullword
    $s869  = "CoordinatorLockingAC4CodeVvgZ" fullword
    $s872  = "convertBoolToObjCBoolyAA0eF0VSbF" fullword
    $s873  = "getGenericMetadata1" fullword
    $s876  = "ContiguousaB0Vy7ElementQzGz" fullword
    $s887  = "UHAWAVAUATSPIIAAHtJH" fullword
    $s891  = "applicationDidResignActive" fullword
    $s893  = "CGContextRelease" fullword
    $s897  = "seekToFileOffset" fullword
    $s902  = "CFURLCopyFileSystemPath" fullword
    $s907  = "ZTSN5boost18thread" fullword
    $s918  = "getInstanceMethod" fullword
    $s920  = "CFDictionaryCreateMutable" fullword
    $s922  = "N5boost6detail11thread" fullword
    $s951  = "UHAWAVAUATSH8IIHH" fullword
    $s956  = "crossCertificatePair" fullword
    $s972  = "viewForTableColumn" fullword
    $s973  = "AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF" fullword
    $s988  = "IORegistryEntryFromPath" fullword
    $s1028 = "getMethodDescription" fullword
    $s1032 = "lengthOfBytesUsingEncoding" fullword
    $s1033 = "dataWithJSONObject" fullword
    $s1034 = "ZBUSystemInformation" fullword
    $s1035 = "setButton1Action" fullword
    $s1048 = "bundleIdentifier" fullword
    $s1059 = "dataUsingEncoding" fullword
    $s1062 = "componentsSeparatedByString" fullword
    $s1071 = "NSFilenamesPboardType" fullword
    $s1075 = "characterIsMember" fullword
    $s1082 = "checkForUpdatesInBackground" fullword
    $s1083 = "setSearchProvider" fullword
    $s1090 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1104 = "DataSetExtensions" fullword
    $s1130 = "reachabilityWithHostName" fullword
    $s1135 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1137 = "NSPropertyListSerialization" fullword
    $s1138 = "initWithCapacity" fullword
    $s1139 = "sSD10FoundationE19" fullword
    $s1148 = "IOPlatformExpertDevice" fullword
    $s1162 = "NSDistantObjectRequest" fullword
    $s1163 = "stringByAppendingPathComponent" fullword
    $s1175 = "componentsJoinedByString" fullword
    $s1184 = "agentDidFinishValidateItem" fullword
    $s1185 = "uriuwfgjZasjXjjgZg" fullword
    $s1186 = "setTitleBarEndColor" fullword
    $s1187 = "initWithNCController" fullword
    $s1188 = "executeWithPrivileges" fullword
    $s1189 = "NSJSONSerialization" fullword
    $s1190 = "updateBackupGroupsCount" fullword
    $s1191 = "kZBZeoAccountLoggedInNotification" fullword
    $s1192 = "timeIntervalSinceDate" fullword
    $s1193 = "cancelAllOperations" fullword
    $s1195 = "textForMessageInDraggedView" fullword
    $s1197 = "removeObjectForKey" fullword
    $s1199 = "setCanChooseDirectories" fullword
    $s1206 = "facebookAccessToken" fullword
    $s1213 = "SecStaticCodeCreateWithPath" fullword
    $s1217 = "NSDraggingSession" fullword
    $s1225 = "NSAssertionHandler" fullword
    $s1238 = "introductionView" fullword
    $s1273 = "IOCreatePlugInInterfaceForService" fullword
    $s1293 = "FindPrevUserEntry" fullword
    $s1294 = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s1296 = "ARARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1305 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1306 = "connectionDidFinishLoading" fullword
    $s1328 = "ZTI15CCoinsViewCache" fullword
    $s1329 = "ZGVZN5boost10filesystem6detail8dot" fullword
    $s1335 = "NSAppleEventManager" fullword
    $s1343 = "ZN5boost19thread" fullword
    $s1352 = "ZTIN2el4base9threading10ThreadSafeE" fullword
    $s1353 = "tIvPFvP11ClientModelS3" fullword
    $s1354 = "SSTTableFileName" fullword
    $s1355 = "3protectExecutableMemoryEPvm" fullword
    $s1362 = "ZN10cryptonote21is" fullword
    $s1367 = "2numBlocksChanged" fullword
    $s1375 = "setInstanceVariableP11objc" fullword
    $s1376 = "initializeClassPair" fullword
    $s1377 = "setScanResultCategory" fullword
    $s1378 = "UHAWAVAUATSHXIcHcH" fullword
    $s1379 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1380 = "N7cocos2d7network13IDownloadTaskE" fullword
    $s1381 = "setDisableAutoUpdatesLabel" fullword
    $s1382 = "setStandardInput" fullword
    $s1385 = "willEncodeRestorableStateWithCoder" fullword
    $s1387 = "unhideAllApplications" fullword
    $s1388 = "applicationShouldOpenUntitledFile" fullword
    $s1396 = "IORegistryEntryGetParentEntry" fullword
    $s1399 = "UBRARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1414 = "caseInsensitiveCompare" fullword
    $s1417 = "initWithSuiteName" fullword
    $s1427 = "fastIndexForKnownKey" fullword
    $s1428 = "CGPathCreateMutable" fullword
    $s1448 = "SecItemCopyMatching" fullword
    $s1453 = "stringWithCapacity" fullword
    $s1456 = "NSUndoManagerProxy" fullword
    $s1463 = "shouldBeRequiredToFailByGestureRecognizer" fullword
    $s1476 = "setTimeoutIntervalForResource" fullword
    $s1503 = "registerClassPair" fullword
    $s1512 = "includingPropertiesForKeys" fullword
    $s1516 = "otherButtonTitles" fullword
    $s1526 = "traitsIcEEE9showmanycEv" fullword
    $s1527 = "didRegisterUserNotificationSettings" fullword
    $s1531 = "UHAWAVAUATSPIIIMthMtcL" fullword
    $s1532 = "objectForKeyP11objc" fullword
    $s1534 = "dataWithContentsOfFile" fullword
    $s1573 = "applicationWillHide" fullword
    $s1586 = "indexOfTabViewItem" fullword
    $s1609 = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s1610 = "whatIsPluginDescription" fullword
    $s1620 = "numberWithUnsignedInteger" fullword
    $s1626 = "sizeOfItemAtPath" fullword
    $s1628 = "didFailToContinueUserActivityWithType" fullword
    $s1629 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1648 = "getImplementation" fullword
    $s1662 = "operatingSystemVersionString" fullword
    $s1663 = "defaultConfiguration" fullword
    $s1672 = "DispatchOnceCounter" fullword
    $s1691 = "createDirectoryAtURL" fullword
    $s1692 = "redirectResponse" fullword
    $s1694 = "NSURLSessionDataTask" fullword
    $s1703 = "JKDictionaryClass" fullword
    $s1705 = "addScriptMessageHandler" fullword
    $s1714 = "kUMPADUserDefaultKeyForStatisticsDisplayTimes" fullword
    $s1726 = "CFStreamCreatePairWithSocket" fullword
    $s1728 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1737 = "commitPreviewingViewController" fullword
    $s1745 = "kSecMatchLimitAll" fullword
    $s1751 = "Vxssruw2Jrrjoh2Fkurph2Ghidxow2Suhihuhqfhv" fullword
    $s1752 = "UIApplicationDidEnterBackgroundNotification" fullword
    $s1755 = "190clEvE15obfuscated" fullword
    $s1758 = "replaceObjectAtIndex" fullword
    $s1759 = "objectAtIndexedSubscriptP7NSArrayP13objc" fullword
    $s1761 = "200521020415Z0P1" fullword
    $s1763 = "kCFCoreFoundationVersionNumber" fullword
    $s1767 = "RGp0SARARARARARA" fullword
    $s1768 = "JcBX2ZiyBahx4RJr4gGw3WIOY" fullword
    $s1787 = "SafariExtensionViewController" fullword
    $s1799 = "NSOperationQueue" fullword
    $s1807 = "IntermediateBuildFilesPath" fullword
    $s1808 = "didUpdateUserActivity" fullword
    $s1814 = "unretainedObject" fullword
    $s1828 = "timerWithTimeInterval" fullword
    $s1834 = "SecTransformExecute" fullword
    $s1854 = "initWithItemsType" fullword
    $s1862 = "applicationDidUnhide" fullword
    $s1882 = "backingScaleFactor" fullword
    $s1883 = "shouldDragDocumentWithEvent" fullword
    $s1885 = "setHTTPShouldHandleCookies" fullword
    $s1889 = "NSStringPboardType" fullword
    $s1894 = "componentsSeparatedByCharactersInSet" fullword
    $s1895 = "downloadTaskWithRequest" fullword
    $s1908 = "CGRectContainsPoint" fullword
    $s1913 = "496e666f2e706c697374" fullword
    $s1918 = "systemVersionString" fullword
    $s1924 = "assertionFailure" fullword
    $s1929 = "sSS10FoundationE4data8encodingSSSgAA4DataVh" fullword
    $s1940 = "numberWithUnsignedInt" fullword
    $s1943 = "UHAWAVAUATSH8MIIL" fullword
    $s1946 = "isExecutableFileAtPath" fullword
    $s1958 = "numberWithUnsignedLong" fullword
    $s1959 = "authenticationPolicy" fullword

  condition:
    ((#s0 <= 1.5)
      and ((#s1 <= 0.5)
        and ((#s2 <= 0.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 0.5)
              and ((#s5 <= 6.5)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 4.0)
                        and ((#s10 <= 1.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.0)
                                  and ((#s15 <= 1.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 1.0)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 0.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 1.5)
                                                      and ((#s25 <= 1.0)
                                                        and ((#s26 <= 1.0)
                                                          and ((#s27 <= 0.5)
                                                            and ((filesize <= 50212.0)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 1.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 1.5)
                                                                            and ((#s36 <= 1.0)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s38 <= 1.0)
                                                                                  and ((filesize <= 50006.0)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 1.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 1.0)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 1.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((#s72 <= 1.0)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 0.5)
                                                                                                                                                                        and ((#s82 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 1.0)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((filesize <= 16380.0)
                                                                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((#s92 <= 0.5)
                                                                                                                                                                                              and ((#s93 <= 0.5)
                                                                                                                                                                                                and ((#s94 <= 1.0)
                                                                                                                                                                                                  and ((#s95 <= 0.5)
                                                                                                                                                                                                    and ((#s30 <= 0.5)
                                                                                                                                                                                                      and ((#s97 <= 0.5)
                                                                                                                                                                                                        and ((#s98 <= 1.0)
                                                                                                                                                                                                          and ((#s99 <= 0.5)
                                                                                                                                                                                                            and ((#s100 <= 0.5)
                                                                                                                                                                                                              and ((#s101 <= 1.0)
                                                                                                                                                                                                                and ((#s102 <= 0.5)
                                                                                                                                                                                                                  and ((filesize > 4222.0)
                                                                                                                                                                                                                    and ((filesize > 4236.0)
                                                                                                                                                                                                                      and ((#s107 <= 0.5)
                                                                                                                                                                                                                        and ((#s108 <= 2.0)
                                                                                                                                                                                                                          and ((filesize <= 5206.5)
                                                                                                                                                                                                                            and ((filesize > 5176.0)
                                                                                                                                                                                                                            ) or (filesize > 5206.5)
                                                                                                                                                                                                                            and ((filesize > 12526.0)
                                                                                                                                                                                                                              and ((filesize <= 12602.0)
                                                                                                                                                                                                                              ))))))))))))))))))))))) or (filesize > 16380.0)
                                                                                                                                                                                  and ((#s136 <= 1.0)
                                                                                                                                                                                    and ((#s137 <= 0.5)
                                                                                                                                                                                      and ((#s138 <= 0.5)
                                                                                                                                                                                        and ((#s139 <= 0.5)
                                                                                                                                                                                          and ((#s140 <= 1.0)
                                                                                                                                                                                            and ((#s141 <= 0.5)
                                                                                                                                                                                              and ((#s142 <= 0.5)
                                                                                                                                                                                                and ((#s90 <= 0.5)
                                                                                                                                                                                                  and ((#s91 <= 0.5)
                                                                                                                                                                                                    and ((#s145 <= 0.5)
                                                                                                                                                                                                      and ((#s63 <= 0.5)
                                                                                                                                                                                                        and ((#s98 <= 0.5)
                                                                                                                                                                                                          and ((filesize <= 16478.0)
                                                                                                                                                                                                            and ((#s149 <= 1.0)
                                                                                                                                                                                                              and ((filesize > 16468.0)
                                                                                                                                                                                                              ) or (#s149 > 1.0)
                                                                                                                                                                                                            ) or (filesize > 16478.0)
                                                                                                                                                                                                            and ((#s88 <= 1.0)
                                                                                                                                                                                                              and ((#s155 <= 0.5)
                                                                                                                                                                                                                and ((#s156 <= 0.5)
                                                                                                                                                                                                                  and ((#s157 <= 0.5)
                                                                                                                                                                                                                    and ((#s158 <= 0.5)
                                                                                                                                                                                                                      and ((#s107 <= 0.5)
                                                                                                                                                                                                                        and ((#s160 <= 0.5)
                                                                                                                                                                                                                          and ((#s161 <= 0.5)
                                                                                                                                                                                                                            and ((#s162 <= 0.5)
                                                                                                                                                                                                                              and ((#s92 <= 0.5)
                                                                                                                                                                                                                                and ((#s30 <= 0.5)
                                                                                                                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                                                                                                                    and ((#s166 <= 0.5)
                                                                                                                                                                                                                                      and ((#s167 <= 1.5)
                                                                                                                                                                                                                                        and ((#s100 <= 0.5)
                                                                                                                                                                                                                                          and ((#s169 <= 0.5)
                                                                                                                                                                                                                                            and ((#s170 <= 0.5)
                                                                                                                                                                                                                                              and ((#s171 <= 1.0)
                                                                                                                                                                                                                                                and ((#s99 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s173 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s174 <= 1.0)
                                                                                                                                                                                                                                                      and ((#s97 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s93 <= 0.5)
                                                                                                                                                                                                                                                          and ((#s101 <= 1.0)
                                                                                                                                                                                                                                                            and ((#s178 <= 1.0)
                                                                                                                                                                                                                                                              and ((#s179 <= 1.0)
                                                                                                                                                                                                                                                                and ((#s5 <= 0.5)
                                                                                                                                                                                                                                                                  and ((#s181 <= 0.5)
                                                                                                                                                                                                                                                                    and ((#s182 <= 0.5)
                                                                                                                                                                                                                                                                      and ((filesize <= 26134.0)
                                                                                                                                                                                                                                                                        and ((filesize <= 26048.0)
                                                                                                                                                                                                                                                                          and ((filesize > 20788.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 20832.0)
                                                                                                                                                                                                                                                                              or (filesize > 20832.0)
                                                                                                                                                                                                                                                                              and ((filesize <= 21672.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 21612.0)
                                                                                                                                                                                                                                                                                  and ((filesize <= 21326.0)
                                                                                                                                                                                                                                                                                    and ((filesize <= 21250.0)
                                                                                                                                                                                                                                                                                      and ((filesize > 21020.0)
                                                                                                                                                                                                                                                                                        and ((filesize <= 21100.0)
                                                                                                                                                                                                                                                                                        )) or (filesize > 21250.0)
                                                                                                                                                                                                                                                                                    )) or (filesize > 21612.0)
                                                                                                                                                                                                                                                                                ) or (filesize > 21672.0)
                                                                                                                                                                                                                                                                                and ((filesize > 25062.0)
                                                                                                                                                                                                                                                                                  and ((filesize <= 25112.0)
                                                                                                                                                                                                                                                                                    or (filesize > 25112.0)
                                                                                                                                                                                                                                                                                    and ((filesize <= 25224.0)
                                                                                                                                                                                                                                                                                      and ((filesize > 25140.0)
                                                                                                                                                                                                                                                                                      ))))))) or (filesize > 26048.0)
                                                                                                                                                                                                                                                                        ) or (filesize > 26134.0)
                                                                                                                                                                                                                                                                        and ((filesize > 32962.0)
                                                                                                                                                                                                                                                                          and ((filesize > 33116.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 38385.0)
                                                                                                                                                                                                                                                                              and ((filesize > 38276.0)
                                                                                                                                                                                                                                                                              )))))) or (#s181 > 0.5)
                                                                                                                                                                                                                                                                  ))))))) or (#s174 > 1.0)
                                                                                                                                                                                                                                                      and ((#s101 <= 1.0)
                                                                                                                                                                                                                                                        and ((filesize <= 19830.0)
                                                                                                                                                                                                                                                        ))))))))))))))))))) or (#s157 > 0.5)
                                                                                                                                                                                                                  )) or (#s155 > 0.5)
                                                                                                                                                                                                              )))))))))))))))))))) or (#s81 > 0.5)
                                                                                                                                                                      ) or (#s80 > 0.5)
                                                                                                                                                                      and ((#s93 <= 2.0)
                                                                                                                                                                        and ((filesize > 27692.0)
                                                                                                                                                                        )))))))))))))) or (#s68 > 0.5)
                                                                                                                                              and ((filesize <= 22066.0)
                                                                                                                                              )) or (#s67 > 0.5)
                                                                                                                                            and ((#s79 <= 1.0)
                                                                                                                                              and ((#s145 <= 0.5)
                                                                                                                                                and ((#s76 <= 0.5)
                                                                                                                                                  and ((#s142 <= 2.0)
                                                                                                                                                    and ((#s293 <= 0.5)
                                                                                                                                                      and ((#s294 <= 0.5)
                                                                                                                                                        and ((#s182 <= 0.5)
                                                                                                                                                          and ((#s73 <= 1.0)
                                                                                                                                                            and ((#s297 <= 0.5)
                                                                                                                                                              and ((#s160 <= 0.5)
                                                                                                                                                                and ((#s84 <= 0.5)
                                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                                    and ((#s97 <= 1.0)
                                                                                                                                                                      and ((#s140 <= 1.0)
                                                                                                                                                                        and ((#s303 <= 0.5)
                                                                                                                                                                          and ((#s70 <= 0.5)
                                                                                                                                                                            and ((#s75 <= 0.5)
                                                                                                                                                                              and ((#s306 <= 0.5)
                                                                                                                                                                                and ((#s67 > 1.5)
                                                                                                                                                                                  and ((#s309 <= 0.5)
                                                                                                                                                                                    and ((#s93 <= 1.0)
                                                                                                                                                                                      and ((filesize <= 36800.0)
                                                                                                                                                                                        and ((#s174 <= 1.0)
                                                                                                                                                                                          and ((filesize <= 36656.0)
                                                                                                                                                                                            and ((#s101 <= 1.0)
                                                                                                                                                                                              and ((#s315 <= 1.0)
                                                                                                                                                                                                and ((#s316 <= 0.5)
                                                                                                                                                                                                  and ((#s67 <= 3.0)
                                                                                                                                                                                                    and ((filesize <= 24000.0)
                                                                                                                                                                                                      and ((filesize > 23824.0)
                                                                                                                                                                                                      ))) or (#s316 > 0.5)
                                                                                                                                                                                                ))) or (filesize > 36656.0)
                                                                                                                                                                                          ))))))))))))))))))))))) or (#s79 > 1.0)
                                                                                                                                              and ((filesize > 38480.0)
                                                                                                                                                and ((#s166 > 1.0)
                                                                                                                                                ))))))) or (#s63 > 1.5)
                                                                                                                                    and ((#s93 <= 1.0)
                                                                                                                                      and ((#s92 <= 0.5)
                                                                                                                                        and ((#s68 <= 0.5)
                                                                                                                                          and ((#s360 > 0.5)
                                                                                                                                          )) or (#s92 > 0.5)
                                                                                                                                      )))) or (#s61 > 0.5)
                                                                                                                              ) or (#s60 > 0.5)
                                                                                                                            )))) or (#s56 > 1.0)
                                                                                                                    ) or (#s55 > 0.5)
                                                                                                                    and ((#s57 <= 0.5)
                                                                                                                      and ((#s374 <= 1.0)
                                                                                                                      ))) or (#s54 > 0.5)
                                                                                                                  and ((#s378 <= 0.5)
                                                                                                                    and ((#s173 <= 0.5)
                                                                                                                      and ((#s138 > 0.5)
                                                                                                                      )))) or (#s53 > 0.5)
                                                                                                              )) or (#s51 > 0.5)
                                                                                                          ) or (#s50 > 0.5)
                                                                                                        ) or (#s49 > 0.5)
                                                                                                        and ((#s66 <= 0.5)
                                                                                                          and ((#s390 <= 0.5)
                                                                                                            and ((#s174 <= 1.0)
                                                                                                              and ((#s71 <= 1.0)
                                                                                                                and ((#s145 <= 1.0)
                                                                                                                  and ((#s95 <= 1.0)
                                                                                                                    and ((filesize <= 27528.0)
                                                                                                                    ) or (#s95 > 1.0)
                                                                                                                  ))))))) or (#s48 > 0.5)
                                                                                                    ) or (#s47 > 0.5)
                                                                                                    and ((#s405 <= 0.5)
                                                                                                      and ((#s360 <= 0.5)
                                                                                                        and ((#s407 > 0.5)
                                                                                                        ) or (#s360 > 0.5)
                                                                                                        and ((#s179 > 0.5)
                                                                                                        )))) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 1.5)
                                                                                              ) or (#s44 > 0.5)
                                                                                            ) or (#s43 > 0.5)
                                                                                            and ((#s139 <= 0.5)
                                                                                            )) or (#s42 > 0.5)
                                                                                        ) or (#s41 > 0.5)
                                                                                      ) or (#s40 > 0.5)
                                                                                    ) or (filesize > 50006.0)
                                                                                    and ((#s423 <= 0.5)
                                                                                      and ((#s97 <= 1.0)
                                                                                        and ((#s75 <= 0.5)
                                                                                          and ((#s59 <= 1.0)
                                                                                            and ((#s427 <= 0.5)
                                                                                              and ((#s88 <= 1.5)
                                                                                              ) or (#s427 > 0.5)
                                                                                            )))))) or (#s38 > 1.0)
                                                                                ) or (#s37 > 0.5)
                                                                              ) or (#s36 > 1.0)
                                                                            ) or (#s35 > 1.5)
                                                                            and ((#s35 <= 3.0)
                                                                              and ((#s84 <= 0.5)
                                                                                and ((#s24 <= 0.5)
                                                                                  and ((filesize > 8760.0)
                                                                                    and ((filesize <= 12452.0)
                                                                                      and ((#s78 > 1.0)
                                                                                      ) or (filesize > 12452.0)
                                                                                      and ((#s66 <= 0.5)
                                                                                        and ((filesize > 15312.0)
                                                                                          and ((filesize <= 26556.0)
                                                                                          )) or (#s66 > 0.5)
                                                                                      ))))))) or (#s34 > 0.5)
                                                                        ) or (#s33 > 0.5)
                                                                        and ((#s76 <= 0.5)
                                                                          and ((#s460 <= 0.5)
                                                                            and ((filesize <= 19048.0)
                                                                            ) or (#s460 > 0.5)
                                                                          ))) or (#s32 > 0.5)
                                                                      and ((#s360 <= 0.5)
                                                                        and ((#s467 <= 0.5)
                                                                        ) or (#s360 > 0.5)
                                                                        and ((#s93 <= 1.0)
                                                                        ))) or (#s31 > 0.5)
                                                                  ) or (#s30 > 1.5)
                                                                  and ((#s100 > 0.5)
                                                                    and ((#s64 <= 0.5)
                                                                      and ((#s477 <= 1.0)
                                                                      ) or (#s64 > 0.5)
                                                                      and ((#s480 > 0.5)
                                                                      )))) or (#s29 > 0.5)
                                                                and ((#s76 <= 0.5)
                                                                  and ((#s67 > 0.5)
                                                                    and ((#s49 <= 0.5)
                                                                      and ((#s407 > 0.5)
                                                                        and ((#s67 > 1.5)
                                                                          and ((#s491 > 1.0)
                                                                          ))) or (#s49 > 0.5)
                                                                      and ((#s138 <= 0.5)
                                                                        and ((#s405 <= 0.5)
                                                                          and ((#s496 <= 0.5)
                                                                          )) or (#s138 > 0.5)
                                                                      ))) or (#s76 > 0.5)
                                                                  and ((#s501 <= 0.5)
                                                                    and ((#s502 <= 17.0)
                                                                      and ((#s89 <= 0.5)
                                                                        and ((#s67 > 1.5)
                                                                          and ((#s57 <= 0.5)
                                                                            and ((#s95 <= 2.0)
                                                                            )))))))) or (filesize > 50212.0)
                                                              and ((#s514 <= 0.5)
                                                                and ((#s515 <= 1.0)
                                                                  and ((#s516 <= 2.0)
                                                                    and ((#s517 <= 0.5)
                                                                      and ((#s518 <= 0.5)
                                                                        and ((#s519 <= 0.5)
                                                                          and ((#s520 <= 0.5)
                                                                            and ((#s31 <= 1.5)
                                                                              and ((#s182 <= 0.5)
                                                                                and ((#s523 <= 0.5)
                                                                                  and ((#s524 <= 0.5)
                                                                                    and ((#s525 <= 0.5)
                                                                                      and ((#s526 <= 0.5)
                                                                                        and ((#s527 <= 0.5)
                                                                                          and ((#s528 <= 0.5)
                                                                                            and ((#s529 <= 0.5)
                                                                                              and ((#s530 <= 0.5)
                                                                                                and ((#s531 <= 0.5)
                                                                                                  and ((#s532 <= 0.5)
                                                                                                    and ((#s68 <= 0.5)
                                                                                                      and ((#s534 <= 1.0)
                                                                                                        and ((#s535 <= 0.5)
                                                                                                          and ((#s536 <= 0.5)
                                                                                                            and ((#s537 <= 9.0)
                                                                                                              and ((#s538 <= 0.5)
                                                                                                                and ((#s539 <= 0.5)
                                                                                                                  and ((#s540 <= 0.5)
                                                                                                                    and ((#s541 <= 0.5)
                                                                                                                      and ((#s542 <= 2.5)
                                                                                                                        and ((#s64 <= 0.5)
                                                                                                                          and ((#s90 <= 0.5)
                                                                                                                            and ((#s360 <= 0.5)
                                                                                                                              and ((#s99 <= 0.5)
                                                                                                                                and ((#s390 <= 0.5)
                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                    and ((#s549 <= 0.5)
                                                                                                                                      and ((#s95 <= 0.5)
                                                                                                                                        and ((#s551 <= 0.5)
                                                                                                                                          and ((#s552 <= 1.0)
                                                                                                                                            and ((#s553 <= 0.5)
                                                                                                                                              and ((#s174 <= 0.5)
                                                                                                                                                and ((#s306 <= 0.5)
                                                                                                                                                  and ((#s102 <= 0.5)
                                                                                                                                                    and ((#s557 <= 0.5)
                                                                                                                                                      and ((#s71 <= 0.5)
                                                                                                                                                        and ((#s77 <= 1.5)
                                                                                                                                                          and ((filesize <= 170316.0)
                                                                                                                                                            and ((#s79 <= 0.5)
                                                                                                                                                              and ((#s562 <= 0.5)
                                                                                                                                                                and ((#s62 <= 1.0)
                                                                                                                                                                  and ((#s73 <= 0.5)
                                                                                                                                                                    and ((#s565 <= 0.5)
                                                                                                                                                                      and ((#s477 <= 1.0)
                                                                                                                                                                        and ((#s97 <= 0.5)
                                                                                                                                                                          and ((#s162 <= 0.5)
                                                                                                                                                                            and ((#s569 <= 0.5)
                                                                                                                                                                              and ((#s570 <= 0.5)
                                                                                                                                                                                and ((#s137 <= 0.5)
                                                                                                                                                                                  and ((#s80 <= 0.5)
                                                                                                                                                                                    and ((#s58 <= 0.5)
                                                                                                                                                                                      and ((#s158 <= 1.0)
                                                                                                                                                                                        and ((#s575 <= 0.5)
                                                                                                                                                                                          and ((#s576 <= 0.5)
                                                                                                                                                                                            and ((#s67 <= 0.5)
                                                                                                                                                                                              and ((#s93 <= 0.5)
                                                                                                                                                                                                and ((#s140 <= 1.0)
                                                                                                                                                                                                  and ((#s66 <= 1.0)
                                                                                                                                                                                                    and ((#s581 <= 0.5)
                                                                                                                                                                                                      and ((#s156 <= 0.5)
                                                                                                                                                                                                        and ((#s294 <= 0.5)
                                                                                                                                                                                                          and ((#s142 <= 1.0)
                                                                                                                                                                                                            and ((#s537 <= 0.5)
                                                                                                                                                                                                              and ((#s460 <= 0.5)
                                                                                                                                                                                                                and ((#s587 <= 0.5)
                                                                                                                                                                                                                  and ((#s588 <= 1.0)
                                                                                                                                                                                                                    and ((#s63 <= 0.5)
                                                                                                                                                                                                                      and ((#s141 <= 0.5)
                                                                                                                                                                                                                        and ((#s32 <= 0.5)
                                                                                                                                                                                                                          and ((#s101 <= 1.0)
                                                                                                                                                                                                                            and ((#s30 <= 1.0)
                                                                                                                                                                                                                              and ((#s75 <= 0.5)
                                                                                                                                                                                                                                and ((#s166 <= 0.5)
                                                                                                                                                                                                                                  and ((#s88 <= 1.0)
                                                                                                                                                                                                                                    and ((#s597 <= 0.5)
                                                                                                                                                                                                                                      and ((#s178 <= 0.5)
                                                                                                                                                                                                                                        and ((#s599 <= 1.0)
                                                                                                                                                                                                                                          and ((#s315 <= 0.5)
                                                                                                                                                                                                                                            and ((#s303 <= 0.5)
                                                                                                                                                                                                                                              and ((#s92 <= 0.5)
                                                                                                                                                                                                                                                and ((filesize <= 99374.0)
                                                                                                                                                                                                                                                  and ((#s604 <= 1.0)
                                                                                                                                                                                                                                                    and ((filesize <= 99224.0)
                                                                                                                                                                                                                                                      and ((filesize > 71036.0)
                                                                                                                                                                                                                                                        and ((#s179 <= 1.0)
                                                                                                                                                                                                                                                          and ((filesize <= 71180.0)
                                                                                                                                                                                                                                                            or (filesize > 71180.0)
                                                                                                                                                                                                                                                            and ((filesize <= 79806.0)
                                                                                                                                                                                                                                                              and ((filesize > 79716.0)
                                                                                                                                                                                                                                                              ))))) or (filesize > 99224.0)
                                                                                                                                                                                                                                                    ))))))))))))))))))))))))))))))))))))))))))))) or (filesize > 170316.0)
                                                                                                                                                            and ((#s58 <= 0.5)
                                                                                                                                                              and ((#s32 <= 0.5)
                                                                                                                                                                and ((#s145 <= 0.5)
                                                                                                                                                                  and ((#s665 <= 0.5)
                                                                                                                                                                    and ((#s160 <= 0.5)
                                                                                                                                                                      and ((#s98 <= 0.5)
                                                                                                                                                                        and ((#s92 <= 0.5)
                                                                                                                                                                          and ((#s139 <= 0.5)
                                                                                                                                                                            and ((#s67 <= 0.5)
                                                                                                                                                                              and ((#s671 <= 1.5)
                                                                                                                                                                                and ((#s460 <= 0.5)
                                                                                                                                                                                  and ((filesize <= 173732.0)
                                                                                                                                                                                    and ((#s597 <= 0.5)
                                                                                                                                                                                      and ((#s30 <= 1.0)
                                                                                                                                                                                        and ((filesize <= 172786.0)
                                                                                                                                                                                          and ((filesize <= 170620.0)
                                                                                                                                                                                          ) or (filesize > 172786.0)
                                                                                                                                                                                        ))) or (filesize > 173732.0)
                                                                                                                                                                                    and ((#s683 <= 1.0)
                                                                                                                                                                                      and ((#s178 <= 0.5)
                                                                                                                                                                                        and ((#s685 <= 0.5)
                                                                                                                                                                                          and ((filesize > 411508.0)
                                                                                                                                                                                            and ((#s688 <= 0.5)
                                                                                                                                                                                              and ((#s137 <= 0.5)
                                                                                                                                                                                                and ((#s136 <= 91.0)
                                                                                                                                                                                                  and ((#s691 <= 1.0)
                                                                                                                                                                                                    and ((#s5 <= 0.5)
                                                                                                                                                                                                      and ((#s166 <= 0.5)
                                                                                                                                                                                                        and ((#s73 <= 1.5)
                                                                                                                                                                                                          and ((#s80 <= 0.5)
                                                                                                                                                                                                            and ((#s63 <= 0.5)
                                                                                                                                                                                                              and ((#s79 <= 2.0)
                                                                                                                                                                                                                and ((#s698 <= 0.5)
                                                                                                                                                                                                                  and ((#s85 <= 0.5)
                                                                                                                                                                                                                    and ((#s162 <= 0.5)
                                                                                                                                                                                                                      and ((#s701 <= 0.5)
                                                                                                                                                                                                                        and ((#s77 <= 0.5)
                                                                                                                                                                                                                          and ((filesize <= 459618.0)
                                                                                                                                                                                                                            and ((#s73 <= 0.5)
                                                                                                                                                                                                                              and ((#s705 <= 0.5)
                                                                                                                                                                                                                                and ((#s30 <= 1.0)
                                                                                                                                                                                                                                  and ((#s88 <= 1.5)
                                                                                                                                                                                                                                    and ((filesize <= 457316.0)
                                                                                                                                                                                                                                      and ((filesize <= 415252.0)
                                                                                                                                                                                                                                      ) or (filesize > 457316.0)
                                                                                                                                                                                                                                    ))))) or (filesize > 459618.0)
                                                                                                                                                                                                                            and ((#s170 <= 0.5)
                                                                                                                                                                                                                              and ((#s718 <= 0.5)
                                                                                                                                                                                                                                and ((filesize <= 622505.0)
                                                                                                                                                                                                                                  and ((filesize <= 615352.0)
                                                                                                                                                                                                                                    and ((#s93 <= 0.5)
                                                                                                                                                                                                                                      and ((#s722 <= 0.5)
                                                                                                                                                                                                                                        and ((#s723 <= 0.5)
                                                                                                                                                                                                                                          and ((#s724 <= 1.0)
                                                                                                                                                                                                                                            and ((filesize <= 467548.0)
                                                                                                                                                                                                                                              and ((#s88 <= 1.0)
                                                                                                                                                                                                                                                and ((#s167 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s597 <= 0.5)
                                                                                                                                                                                                                                                    and ((filesize > 465502.0)
                                                                                                                                                                                                                                                    ))))))))) or (filesize > 615352.0)
                                                                                                                                                                                                                                  ) or (filesize > 622505.0)
                                                                                                                                                                                                                                  and ((#s597 <= 0.5)
                                                                                                                                                                                                                                    and ((#s30 <= 1.0)
                                                                                                                                                                                                                                      and ((#s743 <= 0.5)
                                                                                                                                                                                                                                        and ((#s744 <= 1.0)
                                                                                                                                                                                                                                          and ((#s93 <= 0.5)
                                                                                                                                                                                                                                            and ((#s88 <= 1.0)
                                                                                                                                                                                                                                              and ((#s167 <= 0.5)
                                                                                                                                                                                                                                                and ((filesize > 1654735.5)
                                                                                                                                                                                                                                                  and ((filesize <= 1763827.5)
                                                                                                                                                                                                                                                    or (filesize > 1763827.5)
                                                                                                                                                                                                                                                    and ((filesize <= 1933213.5)
                                                                                                                                                                                                                                                      and ((filesize > 1882885.5)
                                                                                                                                                                                                                                                      ))))))))))))))))))))))) or (#s73 > 1.5)
                                                                                                                                                                                                        ))))))))))))))))))))))))))))) or (#s174 > 0.5)
                                                                                                                                                and ((#s73 <= 0.5)
                                                                                                                                                  and ((#s294 <= 0.5)
                                                                                                                                                    and ((#s557 <= 0.5)
                                                                                                                                                      and ((#s803 <= 0.5)
                                                                                                                                                        and ((#s160 <= 0.5)
                                                                                                                                                          and ((#s805 <= 0.5)
                                                                                                                                                            and ((#s29 <= 0.5)
                                                                                                                                                              and ((#s306 <= 0.5)
                                                                                                                                                                and ((filesize <= 919366.0)
                                                                                                                                                                  and ((#s174 <= 3.0)
                                                                                                                                                                    and ((#s32 <= 0.5)
                                                                                                                                                                      and ((#s80 <= 0.5)
                                                                                                                                                                        and ((#s30 <= 1.0)
                                                                                                                                                                          and ((#s84 <= 0.5)
                                                                                                                                                                            and ((#s35 <= 1.0)
                                                                                                                                                                              and ((#s66 <= 0.5)
                                                                                                                                                                                and ((#s101 <= 1.0)
                                                                                                                                                                                  and ((filesize > 601000.0)
                                                                                                                                                                                    and ((filesize <= 624612.0)
                                                                                                                                                                                    )))))))))) or (filesize > 919366.0)
                                                                                                                                                                  and ((#s5 <= 0.5)
                                                                                                                                                                    and ((#s831 <= 1.0)
                                                                                                                                                                      and ((#s52 <= 0.5)
                                                                                                                                                                        and ((#s97 <= 0.5)
                                                                                                                                                                          and ((#s162 <= 13.5)
                                                                                                                                                                            and ((#s101 <= 1.0)
                                                                                                                                                                              and ((#s35 <= 1.0)
                                                                                                                                                                                and ((#s30 <= 1.0)
                                                                                                                                                                                  and ((filesize <= 3698716.0)
                                                                                                                                                                                  )) or (#s35 > 1.0)
                                                                                                                                                                                and ((filesize <= 1132332.0)
                                                                                                                                                                                )))))))))))) or (#s160 > 0.5)
                                                                                                                                                          and ((#s75 > 0.5)
                                                                                                                                                          ))))))))) or (#s551 > 0.5)
                                                                                                                                          and ((#s32 > 0.5)
                                                                                                                                          ))) or (#s549 > 0.5)
                                                                                                                                    )) or (#s390 > 0.5)
                                                                                                                                  and ((#s869 <= 0.5)
                                                                                                                                    and ((#s75 <= 1.5)
                                                                                                                                      and ((filesize <= 76784.0)
                                                                                                                                        and ((#s872 <= 0.5)
                                                                                                                                          and ((#s873 <= 1.0)
                                                                                                                                            and ((#s565 > 1.0)
                                                                                                                                              and ((#s876 <= 0.5)
                                                                                                                                                and ((filesize > 75632.0)
                                                                                                                                                )))))))))) or (#s360 > 0.5)
                                                                                                                              and ((#s887 <= 0.5)
                                                                                                                                and ((#s58 <= 0.5)
                                                                                                                                  and ((#s162 <= 0.5)
                                                                                                                                    and ((#s97 <= 0.5)
                                                                                                                                      and ((#s891 <= 0.5)
                                                                                                                                        and ((#s59 <= 1.0)
                                                                                                                                          and ((#s893 <= 0.5)
                                                                                                                                            and ((#s138 <= 0.5)
                                                                                                                                              and ((filesize <= 504416.0)
                                                                                                                                                and ((#s79 <= 1.0)
                                                                                                                                                  and ((#s897 <= 0.5)
                                                                                                                                                    and ((#s67 <= 2.5)
                                                                                                                                                      and ((#s63 <= 1.5)
                                                                                                                                                        and ((#s67 > 1.5)
                                                                                                                                                          and ((#s902 <= 0.5)
                                                                                                                                                            and ((#s102 <= 0.5)
                                                                                                                                                              and ((#s93 <= 1.0)
                                                                                                                                                                and ((#s303 <= 0.5)
                                                                                                                                                                  and ((#s89 <= 0.5)
                                                                                                                                                                    and ((#s907 <= 1.5)
                                                                                                                                                                      and ((filesize <= 69504.0)
                                                                                                                                                                        and ((#s872 <= 0.5)
                                                                                                                                                                          and ((#s29 <= 1.0)
                                                                                                                                                                            and ((#s405 <= 0.5)
                                                                                                                                                                              and ((filesize > 68505.0)
                                                                                                                                                                              )))) or (filesize > 69504.0)
                                                                                                                                                                        and ((#s918 <= 1.0)
                                                                                                                                                                          and ((#s294 <= 0.5)
                                                                                                                                                                            and ((#s920 <= 1.0)
                                                                                                                                                                              and ((#s360 <= 1.5)
                                                                                                                                                                                and ((#s922 <= 0.5)
                                                                                                                                                                                  and ((#s80 <= 0.5)
                                                                                                                                                                                    and ((#s378 <= 0.5)
                                                                                                                                                                                      and ((#s77 > 0.5)
                                                                                                                                                                                        and ((filesize > 244685.5)
                                                                                                                                                                                          and ((filesize <= 321685.5)
                                                                                                                                                                                          ))))))))))))))) or (#s102 > 0.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s553 <= 0.5)
                                                                                                                                                                  and ((filesize <= 366888.0)
                                                                                                                                                                  )))))) or (#s63 > 1.5)
                                                                                                                                                        and ((#s951 <= 0.5)
                                                                                                                                                          and ((#s902 <= 1.0)
                                                                                                                                                            and ((#s66 <= 0.5)
                                                                                                                                                              and ((#s67 > 1.5)
                                                                                                                                                                and ((#s956 <= 0.5)
                                                                                                                                                                  and ((filesize > 495712.0)
                                                                                                                                                                  )))))))))))))) or (#s891 > 0.5)
                                                                                                                                        and ((#s101 <= 1.0)
                                                                                                                                          and ((#s972 <= 0.5)
                                                                                                                                            and ((#s973 <= 1.0)
                                                                                                                                              and ((#s565 > 1.0)
                                                                                                                                              )))))))) or (#s887 > 0.5)
                                                                                                                              )) or (#s90 > 0.5)
                                                                                                                            and ((#s67 <= 0.5)
                                                                                                                              and ((#s97 > 1.5)
                                                                                                                                and ((#s951 <= 0.5)
                                                                                                                                  and ((#s988 <= 1.0)
                                                                                                                                    and ((#s907 <= 1.0)
                                                                                                                                      and ((#s303 <= 0.5)
                                                                                                                                        and ((#s30 > 1.5)
                                                                                                                                          and ((filesize > 1925868.0)
                                                                                                                                          ))) or (#s907 > 1.0)
                                                                                                                                    ))))))) or (#s542 > 2.5)
                                                                                                                      ) or (#s541 > 0.5)
                                                                                                                    ) or (#s540 > 0.5)
                                                                                                                  ) or (#s539 > 0.5)
                                                                                                                ) or (#s538 > 0.5)
                                                                                                              ) or (#s537 > 9.0)
                                                                                                            ) or (#s536 > 0.5)
                                                                                                            and ((#s920 > 0.5)
                                                                                                            )) or (#s535 > 0.5)
                                                                                                        ) or (#s534 > 1.0)
                                                                                                      ) or (#s68 > 0.5)
                                                                                                      and ((#s5 <= 0.5)
                                                                                                        and ((#s360 <= 0.5)
                                                                                                          and ((filesize > 622711.5)
                                                                                                          )))) or (#s532 > 0.5)
                                                                                                  ) or (#s531 > 0.5)
                                                                                                ) or (#s530 > 0.5)
                                                                                              )) or (#s528 > 0.5)
                                                                                          ) or (#s527 > 0.5)
                                                                                        )) or (#s525 > 0.5)
                                                                                    ) or (#s524 > 0.5)
                                                                                    and ((#s1028 <= 2.0)
                                                                                    )) or (#s523 > 0.5)
                                                                                ) or (#s182 > 0.5)
                                                                                and ((#s1032 <= 0.5)
                                                                                  and ((#s1033 <= 0.5)
                                                                                    and ((#s1034 <= 1.0)
                                                                                      and ((#s1035 <= 0.5)
                                                                                        and ((#s54 <= 1.5)
                                                                                          and ((#s723 <= 0.5)
                                                                                            and ((#s297 > 0.5)
                                                                                              and ((#s182 > 1.5)
                                                                                                and ((#s477 > 1.0)
                                                                                                  and ((#s76 > 0.5)
                                                                                                    and ((#s501 <= 0.5)
                                                                                                      and ((#s69 <= 0.5)
                                                                                                        and ((#s1048 > 0.5)
                                                                                                          and ((#s54 > 0.5)
                                                                                                          )))))))) or (#s723 > 0.5)
                                                                                            and ((#s66 > 1.0)
                                                                                            )) or (#s54 > 1.5)
                                                                                          and ((#s139 <= 1.0)
                                                                                            and ((#s1059 <= 1.0)
                                                                                              and ((#s58 <= 1.0)
                                                                                                and ((#s67 <= 1.0)
                                                                                                  and ((#s1062 <= 3.0)
                                                                                                  )) or (#s58 > 1.0)
                                                                                              )))) or (#s1035 > 0.5)
                                                                                      ) or (#s1034 > 1.0)
                                                                                    ) or (#s1033 > 0.5)
                                                                                    and ((#s1071 > 1.0)
                                                                                    )) or (#s1032 > 0.5)
                                                                                  and ((#s10 <= 0.5)
                                                                                    and ((#s1075 <= 0.5)
                                                                                      and ((#s102 > 0.5)
                                                                                        and ((#s161 <= 0.5)
                                                                                        ))) or (#s10 > 0.5)
                                                                                    and ((#s1082 <= 0.5)
                                                                                      and ((#s1083 > 1.0)
                                                                                      ))))) or (#s31 > 1.5)
                                                                            ) or (#s520 > 0.5)
                                                                            and ((#s520 <= 1.5)
                                                                              and ((filesize <= 1136792.0)
                                                                                and ((#s1090 <= 0.5)
                                                                                ) or (filesize > 1136792.0)
                                                                              ) or (#s520 > 1.5)
                                                                            )) or (#s519 > 0.5)
                                                                        ) or (#s518 > 0.5)
                                                                      ) or (#s517 > 0.5)
                                                                    ) or (#s516 > 2.0)
                                                                  ) or (#s515 > 1.0)
                                                                ) or (#s514 > 0.5)
                                                              )) or (#s27 > 0.5)
                                                          ) or (#s26 > 1.0)
                                                        ) or (#s25 > 1.0)
                                                      ) or (#s24 > 1.5)
                                                      and ((#s1104 <= 0.5)
                                                        and ((#s179 <= 1.0)
                                                          and ((#s171 <= 1.0)
                                                            and ((#s182 <= 0.5)
                                                              and ((filesize > 14024.0)
                                                                and ((filesize <= 16072.0)
                                                                  or (filesize > 16072.0)
                                                                  and ((filesize > 53008.0)
                                                                  )))))))) or (#s23 > 0.5)
                                                  ) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 1.0)
                                            ) or (#s19 > 0.5)
                                          ) or (#s18 > 0.5)
                                          and ((#s1130 <= 0.5)
                                          )) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                    ) or (#s15 > 1.5)
                                    and ((#s1135 <= 0.5)
                                      and ((#s951 <= 0.5)
                                        and ((#s1137 <= 3.0)
                                          and ((#s1138 <= 0.5)
                                            and ((#s1139 <= 1.0)
                                              and ((#s64 <= 0.5)
                                                and ((#s565 <= 1.0)
                                                  and ((#s89 <= 0.5)
                                                    and ((#s75 <= 0.5)
                                                      and ((#s98 <= 1.0)
                                                        and ((#s405 <= 0.5)
                                                          and ((#s79 <= 1.0)
                                                            and ((#s920 <= 1.0)
                                                              and ((#s1148 <= 0.5)
                                                                and ((#s15 <= 2.5)
                                                                  and ((#s71 <= 1.0)
                                                                  )))))))))) or (#s64 > 0.5)
                                                and ((#s1162 <= 0.5)
                                                  and ((#s1163 <= 0.5)
                                                    and ((#s805 > 1.0)
                                                      and ((#s161 > 0.5)
                                                      ))) or (#s1162 > 0.5)
                                                )) or (#s1139 > 1.0)
                                            ) or (#s1138 > 0.5)
                                            and ((#s688 <= 1.0)
                                              and ((#s360 > 0.5)
                                                and ((#s1175 > 0.5)
                                                )))))))) or (#s14 > 1.0)
                                ) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                              and ((#s1184 <= 0.5)
                                and ((#s1185 <= 0.5)
                                  and ((#s1186 <= 1.5)
                                    and ((#s1187 <= 0.5)
                                      and ((#s1188 <= 1.5)
                                        and ((#s1189 <= 1.0)
                                          and ((#s1190 <= 0.5)
                                            and ((#s1191 <= 0.5)
                                              and ((#s1192 <= 2.5)
                                                and ((#s1193 <= 0.5)
                                                  and ((#s63 <= 0.5)
                                                    and ((#s1195 <= 0.5)
                                                      and ((#s107 <= 0.5)
                                                        and ((#s1197 <= 0.5)
                                                          and ((#s69 <= 0.5)
                                                            and ((#s1199 > 0.5)
                                                              and ((#s1062 > 0.5)
                                                              ))) or (#s1197 > 0.5)
                                                          and ((#s723 <= 0.5)
                                                            and ((#s1206 <= 1.0)
                                                              and ((#s688 <= 1.0)
                                                                and ((#s1048 <= 0.5)
                                                                  and ((#s897 > 0.5)
                                                                  ) or (#s1048 > 0.5)
                                                                  and ((#s902 <= 0.5)
                                                                    and ((#s1213 <= 1.5)
                                                                      and ((#s57 > 0.5)
                                                                        and ((#s67 <= 1.0)
                                                                          and ((#s1217 <= 1.0)
                                                                          ))) or (#s1213 > 1.5)
                                                                    ) or (#s902 > 0.5)
                                                                    and ((filesize <= 282112.0)
                                                                    ))) or (#s688 > 1.0)
                                                                and ((#s1225 <= 1.0)
                                                                  and ((#s1048 <= 0.5)
                                                                  ))) or (#s1206 > 1.0)
                                                            )))) or (#s1195 > 0.5)
                                                    )) or (#s1193 > 0.5)
                                                  and ((#s537 <= 0.5)
                                                    and ((#s102 <= 1.0)
                                                      and ((#s58 <= 0.5)
                                                        and ((#s1238 > 0.5)
                                                        ) or (#s58 > 0.5)
                                                      ) or (#s102 > 1.0)
                                                    ))) or (#s1192 > 2.5)
                                              ) or (#s1191 > 0.5)
                                            ) or (#s1190 > 0.5)
                                          ) or (#s1189 > 1.0)
                                          and ((#s182 > 1.0)
                                            and ((#s805 > 1.0)
                                            ))) or (#s1188 > 1.5)
                                      ) or (#s1187 > 0.5)
                                    ) or (#s1186 > 1.5)
                                  ) or (#s1185 > 0.5)
                                ) or (#s1184 > 0.5)
                              )) or (#s11 > 0.5)
                            and ((#s29 > 1.0)
                            )) or (#s10 > 1.5)
                          and ((#s179 <= 1.5)
                            and ((#s315 <= 0.5)
                            ) or (#s179 > 1.5)
                            and ((#s158 > 1.0)
                            ))) or (#s9 > 4.0)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                    and ((#s71 > 0.5)
                      and ((#s303 <= 0.5)
                        and ((#s8 <= 1.0)
                          and ((#s1273 <= 4.5)
                            and ((#s920 <= 1.0)
                              and ((#s528 <= 0.5)
                                and ((filesize <= 89314.0)
                                  and ((#s16 > 0.5)
                                  )) or (#s528 > 0.5)
                              ) or (#s920 > 1.0)
                            )) or (#s8 > 1.0)
                        )))) or (#s6 > 0.5)
                  and ((#s76 <= 3.0)
                    or (#s76 > 3.0)
                    and ((#s36 > 1.0)
                    ))) or (#s5 > 6.5)
                and ((#s73 <= 1.0)
                  and ((#s918 <= 1.0)
                    and ((#s1293 <= 0.5)
                      and ((#s1294 <= 1.0)
                        and ((#s5 <= 11.5)
                          and ((#s1296 <= 0.5)
                          )) or (#s1294 > 1.0)
                      ) or (#s1293 > 0.5)
                    ) or (#s918 > 1.0)
                  ))) or (#s4 > 0.5)
              and ((#s587 <= 0.5)
                and ((#s1305 <= 1.0)
                  and ((#s1306 <= 0.5)
                    and ((#s805 <= 1.0)
                      and ((#s66 <= 2.5)
                        and ((#s100 <= 0.5)
                          and ((#s107 > 1.0)
                            and ((#s182 <= 0.5)
                            )))) or (#s805 > 1.0)
                      and ((#s1163 > 0.5)
                      )) or (#s1306 > 0.5)
                  ) or (#s1305 > 1.0)
                  and ((#s84 <= 1.5)
                    and ((#s872 > 1.0)
                    ) or (#s84 > 1.5)
                  )))) or (#s3 > 0.5)
            and ((#s77 <= 0.5)
              and ((#s1328 <= 0.5)
                and ((#s1329 <= 0.5)
                  and ((filesize > 4609706.0)
                    and ((#s100 <= 0.5)
                      and ((#s303 <= 0.5)
                        and ((#s102 <= 2.5)
                          and ((#s1335 > 0.5)
                          ))))) or (#s1329 > 0.5)
                  and ((#s907 > 1.0)
                    and ((#s1343 <= 3.0)
                      and ((filesize <= 5007764.0)
                        and ((#s3 <= 3.0)
                        ) or (filesize > 5007764.0)
                      ) or (#s1343 > 3.0)
                    ))) or (#s1328 > 0.5)
              ) or (#s77 > 0.5)
              and ((#s42 <= 0.5)
                and ((#s1352 <= 1.0)
                  and ((#s1353 <= 1.0)
                    and ((#s1354 <= 0.5)
                      and ((#s1355 <= 0.5)
                        and ((#s102 <= 3.5)
                          and ((#s360 <= 0.5)
                          ) or (#s102 > 3.5)
                          and ((#s102 > 7.5)
                            and ((#s1362 > 0.5)
                            ))) or (#s1355 > 0.5)
                      ) or (#s1354 > 0.5)
                    ) or (#s1353 > 1.0)
                    and ((#s1367 <= 1.5)
                      or (#s1367 > 1.5)
                      and ((#s156 > 1.0)
                      ))) or (#s1352 > 1.0)
                )))) or (#s2 > 0.5)
        ) or (#s1 > 0.5)
        and ((#s1375 <= 1.5)
          and ((#s1376 <= 0.5)
            and ((#s1377 <= 0.5)
              and ((#s1378 <= 0.5)
                and ((#s1379 <= 0.5)
                  and ((#s1380 <= 0.5)
                    and ((#s1381 <= 0.5)
                      and ((#s1382 <= 0.5)
                        and ((#s1186 <= 1.5)
                          and ((#s1195 <= 0.5)
                            and ((#s1385 <= 0.5)
                              and ((#s71 <= 7.0)
                                and ((#s1387 <= 1.5)
                                  and ((#s1388 <= 0.5)
                                    and ((#s718 <= 0.5)
                                      and ((#s705 <= 3.5)
                                        and ((#s551 <= 0.5)
                                          and ((#s58 > 0.5)
                                            and ((#s52 <= 0.5)
                                              and ((#s167 <= 1.0)
                                                and ((#s1396 <= 1.0)
                                                  and ((#s78 <= 1.0)
                                                    and ((#s1137 <= 1.0)
                                                      and ((#s1399 <= 0.5)
                                                        and ((#s743 > 1.0)
                                                        )))))))) or (#s551 > 0.5)
                                          and ((#s30 <= 1.0)
                                            and ((#s167 > 1.5)
                                              and ((#s138 <= 0.5)
                                                and ((#s565 <= 2.5)
                                                  and ((#s1414 <= 0.5)
                                                    and ((#s597 > 1.5)
                                                      and ((#s1417 <= 0.5)
                                                        and ((#s182 <= 0.5)
                                                          and ((#s74 > 1.0)
                                                          )))))))) or (#s30 > 1.0)
                                            and ((#s1427 <= 0.5)
                                              and ((#s1428 > 1.5)
                                                and ((#s1071 <= 1.0)
                                                )) or (#s1427 > 0.5)
                                            ))) or (#s705 > 3.5)
                                        and ((#s1427 <= 0.5)
                                          and ((#s360 > 0.5)
                                            and ((#s158 <= 0.5)
                                              and ((#s1163 <= 0.5)
                                                and ((#s360 <= 1.5)
                                                  and ((filesize <= 126816.0)
                                                  )))))))) or (#s1388 > 0.5)
                                    and ((#s1448 <= 1.0)
                                      and ((#s893 <= 1.0)
                                        and ((#s84 <= 0.5)
                                          and ((#s85 <= 0.5)
                                            and ((#s58 <= 0.5)
                                              and ((#s1453 <= 0.5)
                                                and ((#s1335 <= 1.0)
                                                  and ((#s1306 <= 0.5)
                                                    and ((#s1456 > 0.5)
                                                    ) or (#s1306 > 0.5)
                                                  )))) or (#s85 > 0.5)
                                            and ((#s1463 <= 0.5)
                                              and ((#s374 <= 1.0)
                                                and ((#s161 <= 0.5)
                                                  and ((#s918 <= 1.0)
                                                  ))))) or (#s84 > 0.5)
                                          and ((#s378 > 0.5)
                                          ))) or (#s1448 > 1.0)
                                      and ((#s1476 > 1.5)
                                      ))) or (#s1387 > 1.5)
                                ) or (#s71 > 7.0)
                              ) or (#s1385 > 0.5)
                              and ((#s15 <= 1.0)
                                and ((#s65 <= 1.0)
                                  and ((#s182 > 0.5)
                                    and ((#s167 <= 0.5)
                                      and ((#s138 <= 0.5)
                                        and ((#s1048 > 0.5)
                                          and ((filesize <= 10092017.0)
                                          ))) or (#s167 > 0.5)
                                    ))) or (#s15 > 1.0)
                                and ((#s1033 <= 0.5)
                                  and ((#s32 > 0.5)
                                  ) or (#s1033 > 0.5)
                                ))) or (#s1195 > 0.5)
                          ) or (#s1186 > 1.5)
                        ) or (#s1382 > 0.5)
                        and ((#s69 <= 0.5)
                          and ((#s1503 <= 1.0)
                            and ((#s1048 <= 0.5)
                              and ((#s988 <= 1.0)
                              ) or (#s1048 > 0.5)
                              and ((#s95 > 3.0)
                              ))) or (#s69 > 0.5)
                          and ((#s1512 > 1.5)
                          ))) or (#s1381 > 0.5)
                    ) or (#s1380 > 0.5)
                    and ((#s1516 <= 3.0)
                      and ((filesize <= 17756408.0)
                        or (filesize > 17756408.0)
                        and ((filesize > 18004136.0)
                        )) or (#s1516 > 3.0)
                    )) or (#s1379 > 0.5)
                ) or (#s1378 > 0.5)
              ) or (#s1377 > 0.5)
            ) or (#s1376 > 0.5)
            and ((#s1526 <= 1.5)
              and ((#s1527 <= 0.5)
                and ((#s1225 <= 1.5)
                  and ((#s1048 <= 0.5)
                    and ((#s158 <= 1.5)
                      and ((#s1531 <= 0.5)
                        and ((#s1532 <= 0.5)
                          and ((#s805 <= 1.0)
                            and ((#s1534 <= 0.5)
                              and ((#s565 > 2.5)
                                and ((#s1062 <= 0.5)
                                  and ((#s141 <= 1.0)
                                    and ((#s1417 <= 0.5)
                                      and ((#s597 <= 1.0)
                                        and ((#s71 <= 1.0)
                                        )))))) or (#s1534 > 0.5)
                            ) or (#s805 > 1.0)
                          ) or (#s1532 > 0.5)
                          and ((#s360 > 0.5)
                            and ((#s685 <= 0.5)
                              and ((#s139 <= 2.5)
                                and ((#s170 > 0.5)
                                  and ((#s491 <= 1.5)
                                    and ((#s141 > 1.0)
                                      and ((#s1379 <= 0.5)
                                      )))))))) or (#s1531 > 0.5)
                        and ((#s1532 <= 0.5)
                          and ((#s174 <= 1.0)
                            and ((#s1503 > 1.5)
                            )))) or (#s158 > 1.5)
                      and ((#s58 <= 0.5)
                        and ((#s1573 <= 0.5)
                          and ((#s15 <= 0.5)
                            and ((#s1197 <= 1.5)
                              and ((#s156 > 0.5)
                                and ((#s743 > 0.5)
                                ))) or (#s15 > 0.5)
                            and ((#s170 <= 0.5)
                            )) or (#s1573 > 0.5)
                          and ((#s156 <= 0.5)
                            and ((#s1586 <= 0.5)
                              and ((#s10 <= 0.5)
                                and ((#s95 <= 2.0)
                                  and ((#s5 <= 0.5)
                                    and ((#s565 > 1.5)
                                      and ((#s69 <= 0.5)
                                      )) or (#s5 > 0.5)
                                  ) or (#s95 > 2.0)
                                ) or (#s10 > 0.5)
                              )) or (#s156 > 0.5)
                            and ((#s1082 <= 0.5)
                              and ((#s59 <= 1.0)
                                and ((#s47 > 0.5)
                                  and ((#s161 <= 1.0)
                                  )) or (#s59 > 1.0)
                              ) or (#s1082 > 0.5)
                            ))) or (#s58 > 0.5)
                        and ((#s12 <= 0.5)
                          and ((#s1609 <= 0.5)
                            and ((#s1610 <= 0.5)
                              and ((#s71 <= 3.0)
                                and ((#s65 <= 1.0)
                                  and ((#s685 > 1.5)
                                  ) or (#s65 > 1.0)
                                ) or (#s71 > 3.0)
                              ) or (#s1610 > 0.5)
                            )) or (#s12 > 0.5)
                          and ((#s1620 > 1.0)
                          )))) or (#s1048 > 0.5)
                    and ((#s107 <= 0.5)
                      or (#s107 > 0.5)
                      and ((#s100 <= 1.5)
                        and ((#s1626 <= 0.5)
                          and ((#s565 <= 1.5)
                            and ((#s1628 <= 0.5)
                              and ((#s1629 <= 0.5)
                                and ((#s58 > 0.5)
                                ) or (#s1629 > 0.5)
                                and ((#s58 <= 0.5)
                                ))) or (#s565 > 1.5)
                            and ((#s102 <= 0.5)
                              and ((#s100 <= 0.5)
                                and ((#s141 > 1.0)
                                )))) or (#s1626 > 0.5)
                        ) or (#s100 > 1.5)
                        and ((#s685 <= 10.0)
                          and ((#s705 <= 1.5)
                            and ((#s167 <= 4.0)
                              and ((#s1648 <= 1.0)
                                and ((#s54 <= 0.5)
                                  and ((#s378 <= 0.5)
                                    and ((#s1175 <= 0.5)
                                    ) or (#s378 > 0.5)
                                  ) or (#s54 > 0.5)
                                )))) or (#s685 > 10.0)
                          and ((#s91 <= 0.5)
                          ))))) or (#s1225 > 1.5)
                  and ((#s1662 <= 0.5)
                    and ((#s1663 <= 3.0)
                      and ((#s1573 > 0.5)
                        and ((#s1375 > 0.5)
                          and ((#s378 > 0.5)
                            and ((#s293 <= 0.5)
                              and ((#s49 <= 0.5)
                                and ((#s1672 <= 0.5)
                                  and ((filesize > 209280.0)
                                    and ((#s1379 <= 0.5)
                                    )))))))) or (#s1663 > 3.0)
                      and ((#s1175 <= 0.5)
                      )) or (#s1662 > 0.5)
                    and ((#s77 <= 0.5)
                      and ((#s82 <= 0.5)
                        and ((filesize <= 2593944.0)
                        ))))) or (#s1527 > 0.5)
                and ((#s1691 <= 0.5)
                  and ((#s1692 > 4.5)
                    and ((#s1694 <= 2.5)
                      and ((#s1225 > 1.0)
                        and ((#s18 > 0.5)
                        )))) or (#s1691 > 0.5)
                  and ((#s95 > 2.5)
                    and ((#s1703 > 0.5)
                      and ((#s1705 <= 0.5)
                      ))))) or (#s1526 > 1.5)
              and ((#s1048 <= 0.5)
                and ((#s167 > 2.5)
                  and ((#s57 <= 0.5)
                  )) or (#s1048 > 0.5)
                and ((#s1714 > 0.5)
                  and ((#s76 <= 1.5)
                    and ((#s98 <= 3.5)
                      and ((#s49 <= 0.5)
                        and ((#s520 > 2.5)
                        )) or (#s98 > 3.5)
                      and ((#s520 <= 0.5)
                        and ((#s565 <= 2.5)
                          or (#s565 > 2.5)
                          and ((#s1726 <= 1.0)
                            or (#s1726 > 1.0)
                            and ((#s1728 <= 0.5)
                              and ((filesize <= 14051632.0)
                                and ((#s49 <= 0.5)
                                  and ((filesize <= 11259016.0)
                                  )) or (filesize > 14051632.0)
                              )))) or (#s520 > 0.5)
                        and ((#s1737 > 0.5)
                          and ((filesize <= 19809960.0)
                          )))) or (#s76 > 1.5)
                    and ((#s520 <= 0.5)
                      or (#s520 > 0.5)
                      and ((#s1728 <= 0.5)
                        and ((#s1745 > 2.0)
                          and ((#s1090 <= 0.5)
                          ))))))))) or (#s1375 > 1.5)
          and ((#s1751 <= 0.5)
            and ((#s1752 <= 1.0)
              and ((#s496 <= 1.5)
                and ((#s1516 <= 0.5)
                  and ((#s1755 <= 1.0)
                    and ((#s565 <= 3.5)
                      and ((#s139 <= 2.5)
                        and ((#s1758 <= 1.5)
                          and ((#s1759 <= 2.5)
                            and ((#s565 <= 2.0)
                              and ((#s1761 <= 0.5)
                                and ((#s57 <= 2.0)
                                  and ((#s1763 <= 3.0)
                                    and ((#s491 <= 1.0)
                                      and ((#s1526 <= 1.0)
                                        and ((#s15 <= 1.0)
                                          and ((#s1767 <= 0.5)
                                            and ((#s1768 > 0.5)
                                            )))))) or (#s57 > 2.0)
                                  and ((#s918 > 1.5)
                                  ))) or (#s565 > 2.0)
                              and ((#s65 <= 1.0)
                                and ((#s84 <= 0.5)
                                  and ((#s1427 <= 1.5)
                                  ) or (#s84 > 0.5)
                                  and ((#s1767 > 0.5)
                                    and ((#s1787 > 1.5)
                                    )))))) or (#s1758 > 1.5)
                        ) or (#s139 > 2.5)
                        and ((#s569 <= 0.5)
                          and ((#s170 <= 0.5)
                            and ((#s73 <= 0.5)
                              and ((#s138 <= 0.5)
                                and ((#s1048 <= 0.5)
                                  and ((#s297 <= 0.5)
                                    and ((#s1799 <= 1.0)
                                      and ((#s182 <= 0.5)
                                        and ((#s1726 <= 1.0)
                                          and ((#s1135 <= 0.5)
                                            and ((filesize <= 158368.0)
                                              and ((#s58 <= 0.5)
                                                and ((#s167 <= 2.0)
                                                  and ((#s537 <= 0.5)
                                                    and ((#s1807 <= 1.0)
                                                      and ((#s1808 <= 0.5)
                                                        and ((#s49 <= 0.5)
                                                          and ((#s57 <= 0.5)
                                                          ) or (#s49 > 0.5)
                                                        ) or (#s1808 > 0.5)
                                                        and ((#s1814 <= 1.0)
                                                        ))))) or (#s58 > 0.5)
                                              ))) or (#s1726 > 1.0)
                                        )))) or (#s1048 > 0.5)
                                  and ((#s95 <= 2.0)
                                    and ((#s1828 > 0.5)
                                    ) or (#s95 > 2.0)
                                  )) or (#s138 > 0.5)
                                and ((#s405 <= 0.5)
                                  and ((#s803 <= 0.5)
                                    and ((#s1834 <= 1.0)
                                      and ((#s893 <= 1.0)
                                        and ((#s1767 <= 0.5)
                                          and ((#s1199 <= 0.5)
                                            and ((#s1163 <= 0.5)
                                              and ((#s58 > 0.5)
                                              ) or (#s1163 > 0.5)
                                            )) or (#s1767 > 0.5)
                                          and ((#s179 <= 1.0)
                                            or (#s179 > 1.0)
                                            and ((#s5 <= 0.5)
                                              and ((filesize <= 1228136.0)
                                              ))))))) or (#s405 > 0.5)
                                  and ((#s1854 <= 1.0)
                                    and ((#s1135 > 0.5)
                                      and ((#s160 > 1.0)
                                      )) or (#s1854 > 1.0)
                                  )))) or (#s170 > 0.5)
                            and ((#s1862 <= 0.5)
                              and ((#s1137 > 1.0)
                                and ((#s1534 > 1.0)
                                )) or (#s1862 > 0.5)
                              and ((#s501 <= 1.0)
                                and ((#s691 <= 1.0)
                                )))) or (#s569 > 0.5)
                          and ((#s91 <= 1.0)
                            and ((#s12 <= 0.5)
                              and ((#s1059 <= 1.5)
                                and ((#s158 > 1.5)
                                  and ((#s1628 > 0.5)
                                  ))) or (#s12 > 0.5)
                              and ((#s1882 <= 0.5)
                                and ((#s1883 <= 0.5)
                                  or (#s1883 > 0.5)
                                  and ((#s1885 > 0.5)
                                  )))) or (#s91 > 1.0)
                            and ((#s1889 <= 1.0)
                              and ((#s407 > 0.5)
                                and ((#s378 > 0.5)
                                  and ((#s1894 <= 0.5)
                                    and ((#s1895 <= 0.5)
                                      and ((#s5 <= 0.5)
                                        and ((#s360 > 0.5)
                                          and ((#s67 > 1.5)
                                          ))))))) or (#s1889 > 1.0)
                            ))))) or (#s1755 > 1.0)
                  ) or (#s1516 > 0.5)
                  and ((#s1908 <= 1.0)
                    and ((#s1048 > 0.5)
                      and ((#s1 <= 1.5)
                        or (#s1 > 1.5)
                        and ((#s1913 > 1.0)
                        ))))) or (#s496 > 1.5)
                and ((#s1213 <= 1.0)
                  and ((#s1918 <= 1.5)
                    and ((#s182 <= 0.5)
                      and ((#s73 > 1.0)
                      ) or (#s182 > 0.5)
                      and ((#s98 <= 3.5)
                        and ((#s1924 <= 1.0)
                          and ((#s76 <= 2.0)
                            and ((#s1048 <= 0.5)
                              or (#s1048 > 0.5)
                              and ((#s102 <= 0.5)
                                and ((#s1929 <= 1.0)
                                  or (#s1929 > 1.0)
                                  and ((#s75 <= 0.5)
                                  )))))) or (#s98 > 3.5)
                        and ((#s688 <= 1.0)
                        ))) or (#s1918 > 1.5)
                    and ((#s1940 > 0.5)
                    )) or (#s1213 > 1.0)
                  and ((#s1943 <= 0.5)
                    and ((#s89 > 0.5)
                      and ((#s1946 <= 0.5)
                        and ((#s70 <= 1.0)
                          and ((#s1148 > 0.5)
                          )))) or (#s1943 > 0.5)
                  ))) or (#s1752 > 1.0)
              and ((#s29 <= 1.5)
              )) or (#s1751 > 0.5)
          ))) or (#s0 > 1.5)
      and ((#s1958 <= 0.5)
        and ((#s1959 > 5.5)
        )))
}